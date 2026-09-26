// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"errors"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/runner/executor"
)

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
	if err := validate(validJob()); err != nil {
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
	}
	for name, mutate := range cases {
		j := validJob()
		j.Steps = append([]executor.Step(nil), j.Steps...)
		mutate(&j)
		if err := validate(j); !errors.Is(err, executor.ErrInvalidJob) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestNew_RejectsRootUser(t *testing.T) {
	for _, u := range []string{"0:0", "root", "1000", "0:1000", "1000:0"} {
		if _, err := New(nil, Options{User: u}); err == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	e, err := New(nil, Options{})
	if err != nil || e.opts.User != "1000:1000" || e.opts.HelperImage != DefaultHelperImage || e.opts.PidsLimit != 1024 {
		t.Fatalf("defaults = %+v %v", e.opts, err)
	}
}

func TestHardenedHostConfig(t *testing.T) {
	e, _ := New(nil, Options{})
	hc := e.hardened("net", "vol")
	if hc.Privileged || len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" || len(hc.CapAdd) != 0 ||
		hc.SecurityOpt[0] != "no-new-privileges:true" || hc.NetworkMode == "host" || hc.PidMode != "" ||
		*hc.Init != true || hc.Memory != hc.MemorySwap || *hc.PidsLimit != 1024 || len(hc.Binds) != 0 ||
		len(hc.Mounts) != 1 || hc.Mounts[0].Source != "vol" || hc.Mounts[0].Type != "volume" {
		t.Fatalf("host config not hardened: %+v", hc)
	}
}
