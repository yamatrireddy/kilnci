// SPDX-License-Identifier: Apache-2.0

//go:build integration

package docker

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/yamatrireddy/kilnci/runner/executor"
)

const testImage = "alpine:3.22"

func newExecutor(t *testing.T) (*Executor, *client.Client) {
	t.Helper()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	e, err := New(cli, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e, cli
}

var jobSeq = 0

func job(steps ...executor.Step) executor.Job {
	jobSeq++
	id := strings.ToUpper(time.Now().Format("20060102150405")) + strings.Repeat("0", 10)
	id = id[:24] + string(rune('A'+jobSeq%26)) + string(rune('A'+(jobSeq/26)%26))
	return executor.Job{ID: id, Image: testImage, Steps: steps, Timeout: 2 * time.Minute, Env: []executor.EnvVar{{Name: "GREETING", Value: "hi"}}}
}

func run(t *testing.T, e *Executor, j executor.Job) (executor.Result, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := e.Run(t.Context(), j, &out)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	return res, out.String()
}

// TestDocker_SandboxIsHardened checks the ADR-0006 defaults from inside the
// job container.
func TestDocker_SandboxIsHardened(t *testing.T) {
	e, _ := newExecutor(t)
	res, out := run(t, e, job(
		executor.Step{Name: "identity", Run: `echo "uid=$(id -u) gid=$(id -g)"`},
		executor.Step{Name: "caps", Run: `grep -E '^(CapEff|CapPrm|NoNewPrivs)' /proc/self/status`},
		executor.Step{Name: "pids", Run: `cat /sys/fs/cgroup/pids.max 2>/dev/null || true`},
		executor.Step{Name: "workspace", Run: `pwd; touch "$PWD/ok" && echo writable; echo "$GREETING"; ls -ld /var/run/docker.sock 2>&1 || true`},
		executor.Step{Name: "root is blocked", Run: `if su -c true 2>/dev/null; then echo ESCALATED; fi; true`},
	))
	if res.Outcome != executor.Succeeded {
		t.Fatalf("result = %+v\n%s", res, out)
	}
	for _, want := range []string{
		"uid=1000 gid=1000",
		"CapEff:\t0000000000000000",
		"CapPrm:\t0000000000000000",
		"NoNewPrivs:\t1",
		"/workspace", "writable", "hi",
		"No such file or directory", // no Docker socket
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ESCALATED") {
		t.Fatal("job escalated to root")
	}
}

func TestDocker_FailingStepStopsTheJob(t *testing.T) {
	e, _ := newExecutor(t)
	res, out := run(t, e, job(
		executor.Step{Name: "fail", Run: "echo before; exit 3"},
		executor.Step{Name: "never", Run: "echo SHOULD-NOT-RUN"},
	))
	if res.Outcome != executor.Failed || res.ExitCode != 3 || !strings.Contains(res.Reason, `"fail"`) {
		t.Fatalf("result = %+v", res)
	}
	if strings.Contains(out, "SHOULD-NOT-RUN") || !strings.Contains(out, "before") {
		t.Fatalf("output = %s", out)
	}
}

func TestDocker_StepTimeoutAndCancel(t *testing.T) {
	e, _ := newExecutor(t)
	res, _ := run(t, e, job(executor.Step{Name: "slow", Run: "sleep 30", Timeout: 2 * time.Second}))
	if res.Outcome != executor.Failed || !strings.Contains(res.Reason, "timed out") {
		t.Fatalf("timeout result = %+v", res)
	}

	ctx, cancel := context.WithCancel(t.Context())
	j := job(executor.Step{Name: "slow", Run: "sleep 30"})
	go func() {
		time.Sleep(3 * time.Second)
		cancel()
	}()
	var out bytes.Buffer
	res, err := e.Run(ctx, j, &out)
	if err != nil || res.Outcome != executor.Canceled {
		t.Fatalf("cancel result = %+v %v", res, err)
	}
}

func TestDocker_CleansUpEverything(t *testing.T) {
	e, cli := newExecutor(t)
	j := job(executor.Step{Name: "ok", Run: "true"})
	if res, out := run(t, e, j); res.Outcome != executor.Succeeded {
		t.Fatalf("result = %+v\n%s", res, out)
	}
	ctx := t.Context()
	f := client.Filters{}.Add("label", "io.kiln.job="+j.ID)
	cs, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := cli.VolumeList(ctx, client.VolumeListOptions{Filters: f})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := cli.NetworkList(ctx, client.NetworkListOptions{Filters: f})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Items) != 0 || len(vs.Items) != 0 || len(ns.Items) != 0 {
		t.Fatalf("leftovers: %d containers, %d volumes, %d networks", len(cs.Items), len(vs.Items), len(ns.Items))
	}
}

// TestDocker_ChecksOutExactCommit fetches a small public repository at a
// pinned commit (needs network access to github.com).
func TestDocker_ChecksOutExactCommit(t *testing.T) {
	e, _ := newExecutor(t)
	j := job(executor.Step{Name: "read", Run: `cat README; ls -la .git/config && ! grep -qi extraheader .git/config && echo clean-config`})
	j.Checkout = executor.Checkout{
		RepositoryURL: "https://github.com/octocat/Hello-World.git",
		CommitSHA:     "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
	}
	res, out := run(t, e, j)
	if res.Outcome != executor.Succeeded || !strings.Contains(out, "Hello World!") || !strings.Contains(out, "clean-config") {
		t.Fatalf("result = %+v\n%s", res, out)
	}
}
