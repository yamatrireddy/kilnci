// SPDX-License-Identifier: Apache-2.0

// Package docker runs jobs in hardened Docker containers (ADR-0006).
//
// For each job it creates a private bridge network and a named workspace
// volume, prepares the volume's ownership with a single-capability helper,
// checks the commit out with a separate clone container (the only place the
// repository credential ever exists), then runs every step with docker exec
// in one job container. The job container runs as a non-root user with all
// capabilities dropped, no-new-privileges, the runtime's default seccomp and
// AppArmor profiles, an init process, and memory/CPU/PID/disk limits; it has
// no host namespaces, no host mounts, and never the Docker socket. Job
// images are never pulled from loopback, private, or link-local registries,
// since dockerd pulls from the host network. Everything is removed when the
// job ends, whatever the outcome.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"

	"github.com/yamatrireddy/kilnci/runner/executor"
)

// DefaultHelperImage clones repositories and prepares workspaces. It is
// pinned by digest (ADR-0006 §3).
const DefaultHelperImage = "alpine/git:v2.49.1@sha256:c0280cf9572316299b08544065d3bf35db65043d5e3963982ec50647d2746e26"

// Workspace is where the repository is checked out in every container.
const Workspace = "/workspace"

// API is the subset of the Docker client the executor uses.
type API interface {
	ImagePull(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error)
	NetworkCreate(ctx context.Context, name string, opts client.NetworkCreateOptions) (client.NetworkCreateResult, error)
	NetworkRemove(ctx context.Context, id string, opts client.NetworkRemoveOptions) (client.NetworkRemoveResult, error)
	VolumeCreate(ctx context.Context, opts client.VolumeCreateOptions) (client.VolumeCreateResult, error)
	VolumeRemove(ctx context.Context, id string, opts client.VolumeRemoveOptions) (client.VolumeRemoveResult, error)
	ContainerCreate(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error)
	ContainerStart(ctx context.Context, id string, opts client.ContainerStartOptions) (client.ContainerStartResult, error)
	ContainerWait(ctx context.Context, id string, opts client.ContainerWaitOptions) client.ContainerWaitResult
	ContainerKill(ctx context.Context, id string, opts client.ContainerKillOptions) (client.ContainerKillResult, error)
	ContainerRemove(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error)
	ExecCreate(ctx context.Context, containerID string, opts client.ExecCreateOptions) (client.ExecCreateResult, error)
	ExecAttach(ctx context.Context, execID string, opts client.ExecAttachOptions) (client.ExecAttachResult, error)
	ExecInspect(ctx context.Context, execID string, opts client.ExecInspectOptions) (client.ExecInspectResult, error)
	Info(ctx context.Context, opts client.InfoOptions) (client.SystemInfoResult, error)
}

// DefaultUser is the uid:gid jobs run as by default. It is deliberately not
// 1000, which is usually the host's first human user: without user
// namespaces, a container uid equals the host uid, so a job escaping its
// container would own that user's files. 65532 is the conventional
// "nonroot" id of distroless images. Operators should additionally enable
// dockerd's userns-remap so container ids map to an unprivileged host range.
const DefaultUser = "65532:65532"

// Options are runner-operator settings. Operators may lower limits; nothing
// here can grant privileges.
type Options struct {
	HelperImage string
	// User runs the job and clone containers. Must be non-root. Default
	// DefaultUser (65532:65532); see DefaultUser for why, and enable
	// dockerd's userns-remap on runner hosts.
	User        string
	MemoryBytes int64 // default 4 GiB (no swap)
	NanoCPUs    int64 // default 2 CPUs
	PidsLimit   int64 // default 1024
	TmpfsSize   string
	// DiskLimitBytes caps each container's writable layer and the job's
	// workspace volume (default DefaultDiskLimitBytes). It is enforced by
	// dockerd only with the overlay2 storage driver on XFS mounted with
	// pquota; on anything else jobs fail (see Preflight) unless the limit
	// is disabled.
	DiskLimitBytes int64
	// DisableDiskLimit runs jobs without a disk limit, for storage drivers
	// that cannot enforce one. A job can then fill the Docker data root.
	DisableDiskLimit bool
	// RegistryAllowlist lists registries (exact host or host:port) that jobs
	// may pull from even though they are on a loopback, private, or
	// link-local address, such as an internal mirror.
	RegistryAllowlist []string
	// Resolver resolves registry hosts; default net.DefaultResolver.
	Resolver Resolver
	Log      *slog.Logger
}

// Executor runs jobs with Docker.
type Executor struct {
	api               API
	opts              Options
	allowedRegistries map[string]struct{}
}

var userPattern = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)

// New returns an Executor.
func New(api API, opts Options) (*Executor, error) {
	if opts.HelperImage == "" {
		opts.HelperImage = DefaultHelperImage
	}
	if opts.User == "" {
		opts.User = DefaultUser
	}
	if !userPattern.MatchString(opts.User) {
		return nil, errors.New("docker executor: user must be a non-root uid:gid")
	}
	if opts.MemoryBytes <= 0 {
		opts.MemoryBytes = 4 << 30
	}
	if opts.NanoCPUs <= 0 {
		opts.NanoCPUs = 2_000_000_000
	}
	if opts.PidsLimit <= 0 {
		opts.PidsLimit = 1024
	}
	if opts.TmpfsSize == "" {
		opts.TmpfsSize = "1g"
	}
	if opts.DiskLimitBytes <= 0 {
		opts.DiskLimitBytes = DefaultDiskLimitBytes
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	allowed := map[string]struct{}{}
	for _, r := range opts.RegistryAllowlist {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			allowed[r] = struct{}{}
		}
	}
	return &Executor{api: api, opts: opts, allowedRegistries: allowed}, nil
}

var (
	imagePattern   = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	jobIDPattern   = regexp.MustCompile(`^[0-9A-Z]{26}$`)
)

// validate rejects malformed jobs and images from registries the runner
// must not pull from (see checkRegistry). Registry refusals wrap both
// executor.ErrInvalidJob and errRegistryBlocked.
func (e *Executor) validate(ctx context.Context, job executor.Job) error {
	if err := validateSpec(job); err != nil {
		return err
	}
	if err := e.checkRegistry(ctx, job.Image); err != nil {
		return fmt.Errorf("%w: %w", executor.ErrInvalidJob, err)
	}
	return nil
}

// validateSpec checks the job's syntax.
func validateSpec(job executor.Job) error {
	if !jobIDPattern.MatchString(job.ID) || len(job.Image) > 255 || !imagePattern.MatchString(job.Image) || len(job.Steps) == 0 {
		return executor.ErrInvalidJob
	}
	for _, list := range [][]executor.EnvVar{job.Env} {
		for _, e := range list {
			if !envNamePattern.MatchString(e.Name) || strings.ContainsRune(e.Value, 0) {
				return executor.ErrInvalidJob
			}
		}
	}
	for _, s := range job.Steps {
		if s.Run == "" || strings.ContainsRune(s.Run, 0) {
			return executor.ErrInvalidJob
		}
		for _, e := range s.Env {
			if !envNamePattern.MatchString(e.Name) || strings.ContainsRune(e.Value, 0) {
				return executor.ErrInvalidJob
			}
		}
	}
	if co := job.Checkout; co.RepositoryURL != "" {
		u, err := url.Parse(co.RepositoryURL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
			!shaPattern.MatchString(co.CommitSHA) || strings.ContainsAny(co.AuthorizationHeader, "\r\n\x00") {
			return executor.ErrInvalidJob
		}
	}
	return nil
}

// jobResources are the per-job Docker objects to clean up.
type jobResources struct {
	network    string
	volume     string
	containers []string
}

// Run executes the job.
func (e *Executor) Run(ctx context.Context, job executor.Job, out io.Writer) (executor.Result, error) {
	if err := e.validate(ctx, job); err != nil {
		if errors.Is(err, errRegistryBlocked) {
			note(out, "==> %s\n", err)
			return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: "image registry not allowed on this runner"}, nil
		}
		return executor.Result{}, err
	}
	if job.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, job.Timeout, errJobTimeout)
		defer cancel()
	}
	suffix := strings.ToLower(job.ID)
	res := &jobResources{}
	defer e.cleanup(context.WithoutCancel(ctx), res)
	labels := map[string]string{"io.kiln.managed": "true", "io.kiln.job": job.ID}

	// Fail closed if the daemon would silently ignore the disk limit.
	if err := e.checkDiskLimitSupport(ctx); err != nil {
		if errors.Is(err, errDiskLimitUnsupported) {
			e.opts.Log.ErrorContext(ctx, "job disk limit cannot be enforced", "error", err)
			return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: "the runner cannot enforce the job disk limit"}, nil
		}
		return e.infraFailure(ctx, "check disk limit support", err)
	}

	netRes, err := e.api.NetworkCreate(ctx, "kiln-net-"+suffix, client.NetworkCreateOptions{
		Driver: "bridge", Labels: labels,
		// Jobs cannot talk to other containers on the bridge.
		Options: map[string]string{"com.docker.network.bridge.enable_icc": "false"},
	})
	if err != nil {
		return e.infraFailure(ctx, "create network", err)
	}
	res.network = netRes.ID
	// The size option is enforced with an XFS project quota; dockerd rejects
	// it where quotas are unavailable, so the job fails rather than running
	// unlimited.
	vol, err := e.api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: "kiln-ws-" + suffix, Labels: labels, DriverOpts: e.volumeOpts()})
	if err != nil {
		return e.infraFailure(ctx, "create workspace", err)
	}
	res.volume = vol.Volume.Name

	for _, img := range []string{e.opts.HelperImage, job.Image} {
		note(out, "==> Pulling %s\n", img)
		if err := e.pull(ctx, img); err != nil {
			return e.infraFailure(ctx, "pull image "+img, err)
		}
	}
	if err := e.prepareWorkspace(ctx, res, labels); err != nil {
		return e.infraFailure(ctx, "prepare workspace", err)
	}
	if job.Checkout.RepositoryURL != "" {
		note(out, "==> Checking out %s\n", job.Checkout.CommitSHA)
		if r, ok, err := e.checkout(ctx, job, res, labels, out); err != nil || !ok {
			if err != nil {
				return e.infraFailure(ctx, "checkout", err)
			}
			return r, nil
		}
	}

	jobCtr, err := e.startJobContainer(ctx, job, res, labels)
	if err != nil {
		return e.infraFailure(ctx, "start job container", err)
	}
	env := envList(job.Env)
	for i, st := range job.Steps {
		note(out, "==> Step %d/%d: %s\n", i+1, len(job.Steps), st.Name)
		stepCtx, cancel := ctx, context.CancelFunc(func() {})
		if st.Timeout > 0 {
			stepCtx, cancel = context.WithTimeoutCause(ctx, st.Timeout, errStepTimeout)
		}
		code, err := e.exec(stepCtx, jobCtr, execSpec{
			cmd: []string{"/bin/sh", "-e", "-c", st.Run}, env: append(append([]string{}, env...), envList(st.Env)...),
			user: e.opts.User, workdir: Workspace,
		}, out)
		cause := context.Cause(stepCtx)
		cancel()
		if err != nil {
			e.kill(ctx, jobCtr)
			switch {
			case errors.Is(cause, errStepTimeout):
				return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: fmt.Sprintf("step %q timed out after %s", st.Name, st.Timeout)}, nil
			case errors.Is(context.Cause(ctx), errJobTimeout):
				return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: fmt.Sprintf("job timed out after %s", job.Timeout)}, nil
			case ctx.Err() != nil:
				return executor.Result{Outcome: executor.Canceled, ExitCode: -1, Reason: "canceled"}, nil
			default:
				return e.infraFailure(ctx, "run step", err)
			}
		}
		if code != 0 {
			return executor.Result{Outcome: executor.Failed, ExitCode: code, Reason: fmt.Sprintf("step %q failed with exit code %d", st.Name, code)}, nil
		}
	}
	return executor.Result{Outcome: executor.Succeeded, ExitCode: 0}, nil
}

var (
	errJobTimeout  = errors.New("job timeout")
	errStepTimeout = errors.New("step timeout")
)

// infraFailure reports a failure of the executor rather than of the job's
// code. Cancellation while setting up is reported as canceled.
func (e *Executor) infraFailure(ctx context.Context, what string, err error) (executor.Result, error) {
	if ctx.Err() != nil {
		if errors.Is(context.Cause(ctx), errJobTimeout) {
			return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: "job timed out"}, nil
		}
		return executor.Result{Outcome: executor.Canceled, ExitCode: -1, Reason: "canceled"}, nil
	}
	e.opts.Log.WarnContext(ctx, "job infrastructure failure", "step", what, "error", err)
	return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: what + " failed"}, nil
}

func (e *Executor) pull(ctx context.Context, ref string) error {
	// No RegistryAuth: images are pulled anonymously (ADR-0006 §4).
	resp, err := e.api.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer func() { _ = resp.Close() }()
	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

func workspaceMount(volume string) []mount.Mount {
	return []mount.Mount{{Type: mount.TypeVolume, Source: volume, Target: Workspace}}
}

// hardened is the HostConfig shared by every container Kiln starts.
func (e *Executor) hardened(networkMode string, volume string, capAdd ...string) *container.HostConfig {
	init := true
	pids := e.opts.PidsLimit
	return &container.HostConfig{
		NetworkMode:    container.NetworkMode(networkMode),
		Privileged:     false,
		CapDrop:        []string{"ALL"},
		CapAdd:         capAdd,
		SecurityOpt:    []string{"no-new-privileges:true"},
		IpcMode:        "private",
		Init:           &init,
		Mounts:         workspaceMount(volume),
		Tmpfs:          map[string]string{"/tmp": "rw,nosuid,nodev,size=" + e.opts.TmpfsSize},
		LogConfig:      container.LogConfig{Type: "none"},
		ReadonlyRootfs: false,
		Resources: container.Resources{
			Memory: e.opts.MemoryBytes, MemorySwap: e.opts.MemoryBytes, NanoCPUs: e.opts.NanoCPUs, PidsLimit: &pids,
		},
		// Caps the writable layer; dockerd refuses to create the container
		// if the storage driver cannot enforce it.
		StorageOpt: e.storageOpt(),
	}
}

// prepareWorkspace makes the fresh volume writable by the job user. This is
// the only container that starts as root: it keeps only CAP_CHOWN, has no
// network, and runs one fixed command.
func (e *Executor) prepareWorkspace(ctx context.Context, res *jobResources, labels map[string]string) error {
	hc := e.hardened("none", res.volume, "CHOWN")
	c, err := e.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: e.opts.HelperImage, User: "0:0", Entrypoint: []string{"chown"}, Cmd: []string{e.opts.User, Workspace}, Labels: labels,
		},
		HostConfig: hc,
	})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	res.containers = append(res.containers, c.ID)
	if _, err := e.api.ContainerStart(ctx, c.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	code, err := e.wait(ctx, c.ID)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("chown exited %d", code)
	}
	return nil
}

// checkout fetches exactly the commit into the workspace from a dedicated
// clone container. The credential reaches git only through GIT_CONFIG_*
// environment variables of the single fetch exec: never the URL, never a
// credential helper, never .git/config, and the job's env never reaches
// this container. Afterwards .git/config is checked for the credential and
// the job fails closed if it is there (ADR-0006 §3).
func (e *Executor) checkout(ctx context.Context, job executor.Job, res *jobResources, labels map[string]string, out io.Writer) (executor.Result, bool, error) {
	c, err := e.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: e.opts.HelperImage, User: e.opts.User, Entrypoint: []string{"sleep"}, Cmd: []string{"3600"},
			Env: []string{"HOME=/tmp", "GIT_TERMINAL_PROMPT=0"}, Labels: labels,
		},
		HostConfig: e.hardened(res.network, res.volume),
	})
	if err != nil {
		return executor.Result{}, false, fmt.Errorf("create clone container: %w", err)
	}
	res.containers = append(res.containers, c.ID)
	if _, err := e.api.ContainerStart(ctx, c.ID, client.ContainerStartOptions{}); err != nil {
		return executor.Result{}, false, fmt.Errorf("start clone container: %w", err)
	}
	co := job.Checkout
	var fetchEnv []string
	if co.AuthorizationHeader != "" {
		fetchEnv = []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: " + co.AuthorizationHeader}
	}
	steps := []execSpec{
		{cmd: []string{"git", "init", "-q", Workspace}},
		{cmd: []string{"git", "-C", Workspace, "fetch", "-q", "--no-tags", "--depth=1", "--no-recurse-submodules", "--", co.RepositoryURL, co.CommitSHA}, env: fetchEnv},
		{cmd: []string{"git", "-C", Workspace, "-c", "advice.detachedHead=false", "checkout", "-q", "--detach", co.CommitSHA, "--"}},
	}
	for _, s := range steps {
		s.user, s.workdir = e.opts.User, Workspace
		code, err := e.exec(ctx, c.ID, s, out)
		if err != nil {
			return executor.Result{}, false, err
		}
		if code != 0 {
			return executor.Result{Outcome: executor.Failed, ExitCode: code, Reason: "checkout failed"}, false, nil
		}
	}
	if co.AuthorizationHeader != "" {
		var cfg strings.Builder
		if _, err := e.exec(ctx, c.ID, execSpec{cmd: []string{"cat", Workspace + "/.git/config"}, user: e.opts.User, workdir: Workspace}, &cfg); err != nil {
			return executor.Result{}, false, err
		}
		if strings.Contains(cfg.String(), co.AuthorizationHeader) {
			return executor.Result{Outcome: executor.Failed, ExitCode: -1, Reason: "checkout left a credential in the workspace"}, false, nil
		}
	}
	e.remove(ctx, c.ID)
	res.containers = res.containers[:len(res.containers)-1]
	return executor.Result{}, true, nil
}

func (e *Executor) startJobContainer(ctx context.Context, job executor.Job, res *jobResources, labels map[string]string) (string, error) {
	c, err := e.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			// No container-level WorkingDir: Docker would re-create the mount
			// point owned by root. Each exec sets the working directory.
			Image: job.Image, User: e.opts.User, Labels: labels,
			Env: []string{"HOME=/tmp/home"},
			// Keep the container alive; steps run through exec. /bin/sh is
			// required by the pipeline spec.
			Entrypoint: []string{"/bin/sh", "-c", "mkdir -p \"$HOME\"; while :; do sleep 3600; done"},
			Cmd:        []string{},
		},
		HostConfig: e.hardened(res.network, res.volume),
	})
	if err != nil {
		return "", fmt.Errorf("create: %w", err)
	}
	res.containers = append(res.containers, c.ID)
	if _, err := e.api.ContainerStart(ctx, c.ID, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("start: %w", err)
	}
	return c.ID, nil
}

type execSpec struct {
	cmd     []string
	env     []string
	user    string
	workdir string
}

// exec runs cmd in a container, streaming combined output to out, and
// returns its exit code. If ctx ends first it returns ctx's error.
func (e *Executor) exec(ctx context.Context, containerID string, s execSpec, out io.Writer) (int, error) {
	created, err := e.api.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		User: s.user, AttachStdout: true, AttachStderr: true, Env: s.env, WorkingDir: s.workdir, Cmd: s.cmd,
	})
	if err != nil {
		return 0, fmt.Errorf("exec create: %w", err)
	}
	att, err := e.api.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return 0, fmt.Errorf("exec attach: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := stdcopy.StdCopy(out, out, att.Reader)
		done <- err
	}()
	select {
	case err := <-done:
		att.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("exec output: %w", err)
		}
	case <-ctx.Done():
		att.Close()
		<-done
		return 0, fmt.Errorf("exec: %w", context.Cause(ctx))
	}
	insp, err := e.api.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("exec inspect: %w", err)
	}
	return insp.ExitCode, nil
}

func (e *Executor) wait(ctx context.Context, id string) (int, error) {
	w := e.api.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case r := <-w.Result:
		return int(r.StatusCode), nil
	case err := <-w.Error:
		return 0, fmt.Errorf("wait: %w", err)
	case <-ctx.Done():
		return 0, fmt.Errorf("wait: %w", context.Cause(ctx))
	}
}

func (e *Executor) kill(ctx context.Context, id string) {
	kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_, _ = e.api.ContainerKill(kctx, id, client.ContainerKillOptions{})
}

func (e *Executor) remove(ctx context.Context, id string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	if _, err := e.api.ContainerRemove(rctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
		e.opts.Log.WarnContext(ctx, "remove container", "error", err)
	}
}

// cleanup removes every per-job object, even if ctx was canceled.
func (e *Executor) cleanup(ctx context.Context, res *jobResources) {
	for _, id := range res.containers {
		e.remove(ctx, id)
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if res.volume != "" {
		if _, err := e.api.VolumeRemove(cctx, res.volume, client.VolumeRemoveOptions{Force: true}); err != nil {
			e.opts.Log.WarnContext(ctx, "remove workspace volume", "error", err)
		}
	}
	if res.network != "" {
		if _, err := e.api.NetworkRemove(cctx, res.network, client.NetworkRemoveOptions{}); err != nil {
			e.opts.Log.WarnContext(ctx, "remove job network", "error", err)
		}
	}
}

// note writes a runner status line into the job log. Log sink errors are
// surfaced by the sink itself, so they are ignored here.
func note(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

func envList(vars []executor.EnvVar) []string {
	out := make([]string, len(vars))
	for i, v := range vars {
		out[i] = v.Name + "=" + v.Value
	}
	return out
}
