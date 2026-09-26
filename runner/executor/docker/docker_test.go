// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/yamatrireddy/kilnci/runner/executor"
)

// fakeResolver answers from a fixed table; unknown names fail, as they
// would with no network.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = netip.MustParseAddr(a)
	}
	return out, nil
}

var testDNS = fakeResolver{
	"docker.io":           {"44.208.254.194"},
	"ghcr.io":             {"140.82.112.33", "2606:50c0:8000::154"},
	"registry.example":    {"93.184.215.14"},
	"rebind.example":      {"93.184.215.14", "10.1.2.3"},
	"metadata.example":    {"169.254.169.254"},
	"mapped.example":      {"::ffff:127.0.0.1"},
	"cgnat.example":       {"100.100.100.200"},
	"mirror.corp.example": {"10.20.30.40"},
}

// fakeAPI implements the Docker calls the unit tests reach; any other call
// panics on the nil embedded interface.
type fakeAPI struct {
	API
	info    system.Info
	infoErr error
}

func (f *fakeAPI) Info(context.Context, client.InfoOptions) (client.SystemInfoResult, error) {
	return client.SystemInfoResult{Info: f.info}, f.infoErr
}

func newTestExecutor(t *testing.T, opts Options) *Executor {
	t.Helper()
	if opts.Resolver == nil {
		opts.Resolver = testDNS
	}
	e, err := New(&fakeAPI{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func validJob() executor.Job {
	return executor.Job{
		ID: "01K6A7B8C9D0E1F2G3H4J5K6M7", Image: "golang:1.27",
		Steps: []executor.Step{{Name: "s", Run: "true"}},
		Checkout: executor.Checkout{
			RepositoryURL: "https://github.com/acme/app.git", CommitSHA: strings.Repeat("a", 40),
			AuthorizationHeader: "basic eC1hY2Nlc3MtdG9rZW46dA==",
		},
	}
}

func TestValidate(t *testing.T) {
	e := newTestExecutor(t, Options{})
	if err := e.validate(t.Context(), validJob()); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	cases := map[string]func(*executor.Job){
		"bad id":             func(j *executor.Job) { j.ID = "../../x" },
		"image injection":    func(j *executor.Job) { j.Image = "alpine --privileged" },
		"no steps":           func(j *executor.Job) { j.Steps = nil },
		"empty step":         func(j *executor.Job) { j.Steps[0].Run = "" },
		"nul in script":      func(j *executor.Job) { j.Steps[0].Run = "a\x00b" },
		"bad env name":       func(j *executor.Job) { j.Env = []executor.EnvVar{{Name: "A=B", Value: "x"}} },
		"bad step env":       func(j *executor.Job) { j.Steps[0].Env = []executor.EnvVar{{Name: "1X", Value: "x"}} },
		"http url":           func(j *executor.Job) { j.Checkout.RepositoryURL = "http://github.com/acme/app.git" },
		"url credentials":    func(j *executor.Job) { j.Checkout.RepositoryURL = "https://user:pw@github.com/acme/app.git" },
		"option injection":   func(j *executor.Job) { j.Checkout.RepositoryURL = "--upload-pack=touch /tmp/x" },
		"short sha":          func(j *executor.Job) { j.Checkout.CommitSHA = "abc" },
		"header smuggling":   func(j *executor.Job) { j.Checkout.AuthorizationHeader = "basic x\r\nX-Evil: 1" },
		"ref instead of sha": func(j *executor.Job) { j.Checkout.CommitSHA = "refs/heads/main" },
		"loopback registry":  func(j *executor.Job) { j.Image = "127.0.0.1:5000/x" },
	}
	for name, mutate := range cases {
		j := validJob()
		j.Steps = append([]executor.Step(nil), j.Steps...)
		mutate(&j)
		if err := e.validate(t.Context(), j); !errors.Is(err, executor.ErrInvalidJob) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestValidate_ImageRegistry(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("ab", 32)
	tests := []struct {
		image     string
		allowlist []string
		allowed   bool
	}{
		{image: "127.0.0.1:5000/x"},
		{image: "169.254.169.254/x"},
		{image: "[::1]:5000/x"},
		{image: "10.0.0.5:8080/x"},
		{image: "192.168.1.10/team/app:1"},
		{image: "172.16.0.1:443/x"},
		{image: "100.100.100.200/x"},
		{image: "0.0.0.0:5000/x"},
		{image: "localhost:5000/x"},
		{image: "localhost/x"},
		{image: "registry.localhost:5000/x"},
		{image: "metadata.example/x"},
		{image: "rebind.example/x"},       // any blocked address rejects
		{image: "mapped.example/x"},       // IPv4-mapped loopback
		{image: "cgnat.example/x"},        // CGNAT / Alibaba metadata
		{image: "unresolvable.example/x"}, // lookup fails: fail closed
		{image: "LOCALHOST/x"},            // Docker reads upper case as a host; imagePattern must refuse it
		{image: "Metadata/x"},
		{image: "user@registry.example/x"},
		{image: "[fe80::1%eth0]:5000/x"},
		{image: "mirror.corp.example:5000/x", allowlist: []string{"mirror.corp.example"}}, // port must match too
		{image: "docker.io/library/alpine", allowed: true},
		{image: "alpine:3.20", allowed: true},
		{image: "library/alpine:3.20", allowed: true},
		{image: "ghcr.io/o/i" + digest, allowed: true},
		{image: "registry.example:5000/team/app:1.2", allowed: true},
		{image: "93.184.215.14:5000/x", allowed: true},
		{image: "mirror.corp.example:5000/x", allowlist: []string{"Mirror.Corp.Example:5000"}, allowed: true},
		{image: "10.0.0.5:8080/x", allowlist: []string{"10.0.0.5:8080"}, allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.image+"/"+strings.Join(tt.allowlist, ","), func(t *testing.T) {
			e := newTestExecutor(t, Options{RegistryAllowlist: tt.allowlist})
			j := validJob()
			j.Image = tt.image
			err := e.validate(t.Context(), j)
			if tt.allowed && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tt.allowed && !errors.Is(err, executor.ErrInvalidJob) {
				t.Fatalf("accepted: err = %v", err)
			}
		})
	}
}

func TestRun_BlockedRegistryFailsJobWithReason(t *testing.T) {
	e := newTestExecutor(t, Options{})
	j := validJob()
	j.Image = "169.254.169.254/x"
	var out strings.Builder
	res, err := e.Run(t.Context(), j, &out)
	if err != nil || res.Outcome != executor.Failed || !strings.Contains(res.Reason, "registry") {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if !strings.Contains(out.String(), "169.254.169.254") {
		t.Fatalf("job log does not explain the refusal: %q", out.String())
	}
}

func TestNew_RejectsRootUser(t *testing.T) {
	for _, u := range []string{"0:0", "root", "1000", "0:1000", "1000:0"} {
		if _, err := New(nil, Options{User: u}); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	e, err := New(nil, Options{})
	if err != nil || e.opts.User != "65532:65532" || e.opts.HelperImage != DefaultHelperImage || e.opts.PidsLimit != 1024 ||
		e.opts.DiskLimitBytes != 10<<30 || e.opts.DisableDiskLimit || e.opts.Resolver == nil {
		t.Fatalf("defaults = %+v %v", e.opts, err)
	}
}

func TestHardenedHostConfig(t *testing.T) {
	e, _ := New(nil, Options{})
	hc := e.hardened("net", "vol")
	if hc.Privileged || len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" || len(hc.CapAdd) != 0 ||
		hc.SecurityOpt[0] != "no-new-privileges:true" || hc.NetworkMode == "host" || hc.PidMode != "" ||
		*hc.Init != true || hc.Memory != hc.MemorySwap || *hc.PidsLimit != 1024 || len(hc.Binds) != 0 ||
		len(hc.Mounts) != 1 || hc.Mounts[0].Source != "vol" || hc.Mounts[0].Type != "volume" ||
		hc.StorageOpt["size"] != strconv.FormatInt(10<<30, 10) {
		t.Fatalf("host config not hardened: %+v", hc)
	}
}

func TestDiskLimitOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string // "" means no size option
	}{
		{"default", Options{}, "10737418240"},
		{"custom", Options{DiskLimitBytes: 2 << 30}, "2147483648"},
		{"disabled", Options{DisableDiskLimit: true}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestExecutor(t, tt.opts)
			for what, opts := range map[string]map[string]string{
				"container": e.hardened("n", "v").StorageOpt, "volume": e.volumeOpts(),
			} {
				if got := opts["size"]; got != tt.want {
					t.Errorf("%s size = %q, want %q", what, got, tt.want)
				}
				if tt.want == "" && len(opts) != 0 {
					t.Errorf("%s options = %v, want none", what, opts)
				}
			}
		})
	}
}

func TestPreflight_DiskLimitSupport(t *testing.T) {
	xfs := [][2]string{{"Backing Filesystem", "xfs"}, {"Supports d_type", "true"}}
	tests := []struct {
		name     string
		info     system.Info
		infoErr  error
		disabled bool
		wantErr  bool
	}{
		{name: "overlay2 on xfs", info: system.Info{Driver: "overlay2", DriverStatus: xfs}},
		{name: "overlay2 on ext4", info: system.Info{Driver: "overlay2", DriverStatus: [][2]string{{"Backing Filesystem", "extfs"}}}, wantErr: true},
		{name: "containerd snapshotter ignores StorageOpt", info: system.Info{Driver: "overlayfs", DriverStatus: [][2]string{{"driver-type", "io.containerd.snapshotter.v1"}}}, wantErr: true},
		{name: "vfs", info: system.Info{Driver: "vfs"}, wantErr: true},
		{name: "daemon unreachable", infoErr: errors.New("connection refused"), wantErr: true},
		{name: "disabled skips the check", info: system.Info{Driver: "vfs"}, disabled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := New(&fakeAPI{info: tt.info, infoErr: tt.infoErr}, Options{DisableDiskLimit: tt.disabled, Resolver: testDNS})
			if err != nil {
				t.Fatal(err)
			}
			err = e.Preflight(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Preflight = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.infoErr == nil && !strings.Contains(err.Error(), "--job-disk-limit=off") {
				t.Fatalf("error does not tell the operator how to proceed: %v", err)
			}
		})
	}
}

func TestRun_UnsupportedDiskLimitFailsClosed(t *testing.T) {
	e, err := New(&fakeAPI{info: system.Info{Driver: "overlayfs"}}, Options{Resolver: testDNS})
	if err != nil {
		t.Fatal(err)
	}
	// fakeAPI panics on any container call, so reaching one fails the test.
	res, err := e.Run(t.Context(), validJob(), &strings.Builder{})
	if err != nil || res.Outcome != executor.Failed || !strings.Contains(res.Reason, "disk limit") {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

func TestParseDiskLimit(t *testing.T) {
	tests := []struct {
		in       string
		want     int64
		disabled bool
		wantErr  bool
	}{
		{in: "10G", want: 10 << 30},
		{in: "10GiB", want: 10 << 30},
		{in: "10gb", want: 10 << 30},
		{in: "512m", want: 512 << 20},
		{in: "1T", want: 1 << 40},
		{in: "10737418240", want: 10 << 30},
		{in: "off", disabled: true},
		{in: "OFF", disabled: true},
		{in: "0", wantErr: true},
		{in: "-1G", wantErr: true},
		{in: "", wantErr: true},
		{in: "G", wantErr: true},
		{in: "10X", wantErr: true},
		{in: "10GG", wantErr: true},
		{in: "99999999999T", wantErr: true},
		{in: "64M", want: 64 << 20},
		{in: "63M", wantErr: true}, // below the minimum: every job would fail
		{in: "1", wantErr: true},
		{in: "10i", wantErr: true},
		{in: "10ib", wantErr: true},
		{in: "+5G", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, disabled, err := ParseDiskLimit(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want || disabled != tt.disabled {
				t.Fatalf("ParseDiskLimit(%q) = %d, %v, %v", tt.in, got, disabled, err)
			}
		})
	}
}
