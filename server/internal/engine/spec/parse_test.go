// SPDX-License-Identifier: Apache-2.0

package spec

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testdata holds the fixtures; reading through an fs.FS confines paths to it.
var testdata = os.DirFS("testdata")

func TestParse_ValidFixtures(t *testing.T) {
	files, err := fs.Glob(testdata, "valid/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no valid fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := fs.ReadFile(testdata, f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data); err != nil {
				t.Fatalf("Parse: %v", err)
			}
		})
	}
}

// TestParse_MaliciousFixtures: every fixture in testdata/invalid declares the
// problem it must produce in an "# expect:" header.
func TestParse_MaliciousFixtures(t *testing.T) {
	files, err := fs.Glob(testdata, "invalid/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no invalid fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := fs.ReadFile(testdata, f)
			if err != nil {
				t.Fatal(err)
			}
			var expect string
			for line := range strings.SplitSeq(string(data), "\n") {
				if s, ok := strings.CutPrefix(line, "# expect: "); ok {
					expect = strings.TrimSpace(s)
				}
			}
			if expect == "" {
				t.Fatal("fixture has no '# expect:' header")
			}
			_, err = Parse(data)
			var pe *Error
			if !errors.As(err, &pe) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse err = %v, want *Error", err)
			}
			if !strings.Contains(err.Error(), expect) {
				t.Fatalf("error %q does not contain %q", err, expect)
			}
		})
	}
}

func TestParse_FullPipeline(t *testing.T) {
	data, err := fs.ReadFile(testdata, "valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Jobs) != 3 || pl.Jobs[0].ID != "lint" || pl.Jobs[1].ID != "test" || pl.Jobs[2].ID != "deploy" {
		t.Fatalf("jobs = %+v", pl.Jobs)
	}
	test := pl.Jobs[1]
	if test.Image != "golang:1.27" || test.Timeout != 20*time.Minute || test.Retries != 1 ||
		!slices.Equal(test.RunsOn, []string{"amd64", "linux"}) || !slices.Equal(test.Needs, []string{"lint"}) {
		t.Fatalf("test job = %+v", test)
	}
	if test.Steps[0].Name != "Unit tests" || test.Steps[0].Timeout != 10*time.Minute ||
		test.Steps[0].Env[0] != (EnvVar{Name: "VERBOSE", Value: "true"}) {
		t.Fatalf("step = %+v", test.Steps[0])
	}
	if pl.Jobs[0].Timeout != DefaultJobTimeout || pl.Jobs[0].Steps[0].Name != "golangci-lint run ./..." {
		t.Fatalf("defaults not applied: %+v", pl.Jobs[0])
	}
	if !slices.Equal(pl.Env, []EnvVar{{"GOFLAGS", "-mod=readonly"}, {"RETRIES", "3"}}) {
		t.Fatalf("env = %+v", pl.Env)
	}
	if !pl.On.MatchesPush("main") || !pl.On.MatchesPush("release/1.2") || pl.On.MatchesPush("release/1/2") ||
		pl.On.MatchesPush("feature") || !pl.On.MatchesPullRequest("main") || pl.On.MatchesPullRequest("dev") {
		t.Fatalf("trigger matching wrong: %+v", pl.On)
	}
}

func TestParse_TriggerDefaults(t *testing.T) {
	const base = "version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{run: x}]\n"
	pl, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if !pl.On.MatchesPush("anything") || !pl.On.MatchesPullRequest("anything") {
		t.Fatal("omitted `on` must match every push and pull request")
	}
	pl, err = Parse([]byte("on: {}\n" + base))
	if err != nil {
		t.Fatal(err)
	}
	if pl.On.MatchesPush("main") || pl.On.MatchesPullRequest("main") {
		t.Fatal("empty `on` must match nothing")
	}
}

func TestParse_Limits(t *testing.T) {
	cases := map[string]struct {
		doc  string
		want string
	}{
		"too large":             {strings.Repeat("#", MaxBytes+1), "exceeds"},
		"too deep":              {"version: 1\njobs: " + strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2), "nested deeper"},
		"too many nodes":        {"version: 1\nenv: [" + strings.Repeat("1,", MaxNodes) + "1]\njobs: {}", "more than"},
		"nul byte":              {"version: 1\x00", "NUL"},
		"invalid utf8":          {"version: \xff", "UTF-8"},
		"empty":                 {"", "empty"},
		"only comment":          {"# nothing", "empty"},
		"too many jobs":         {"version: 1\njobs:\n" + manyJobs(MaxJobs+1), "1-50 jobs"},
		"run too long":          {"version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{run: " + strings.Repeat("x", MaxRunBytes+1) + "}]", "at most 64 KiB"},
		"step timeout over job": {"version: 1\njobs:\n  a:\n    image: alpine\n    timeout: 5m\n    steps: [{run: x, timeout: 10m}]", "between 1s and 5m0s"},
		"control char in name":  {"version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{name: \"a\\u001b[31m\", run: x}]", "control characters"},
		"bidi override in name": {"version: 1\njobs:\n  a:\n    image: alpine\n    steps: [{name: \"safe\\u202eexe.txt\", run: x}]", "control characters"},
		"null value":            {"version: 1\njobs:\n  a:\n    image:\n    steps: [{run: x}]", "must be a string"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse err = %v, want mention of %q", err, c.want)
			}
		})
	}
}

func manyJobs(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "  j%d:\n    image: alpine\n    steps: [{run: x}]\n", i)
	}
	return b.String()
}

// TestParse_ErrorsNeverEchoValues: attacker-controlled values must not be
// reflected in error messages (they end up in commit statuses and the UI).
func TestParse_ErrorsNeverEchoValues(t *testing.T) {
	const marker = "SECRETMARKER<script>"
	docs := []string{
		"version: 1\njobs:\n  a:\n    image: \"" + marker + "\"\n    steps: [{run: x}]",
		"version: 1\n\"" + marker + "\": 1\njobs: {}",
		"version: 1\nenv:\n  \"" + marker + "\": x\njobs: {}",
		"version: 1\njobs:\n  a:\n    image: alpine\n    timeout: \"" + marker + "\"\n    steps: [{run: x}]",
		"version: 1\njobs: [\"" + marker,
		"version: 1\njobs:\n  a:\n    image: alpine\n    runs-on: [\"" + marker + "\"]\n    steps: [{run: x}]",
	}
	for _, d := range docs {
		_, err := Parse([]byte(d))
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", d)
		}
		if strings.Contains(err.Error(), "SECRETMARKER") {
			t.Fatalf("error echoes document content: %v", err)
		}
	}
}

func TestParse_ReportsManyProblemsButBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n")
	for i := range MaxJobs {
		fmt.Fprintf(&b, "  j%d:\n    image: \"bad image\"\n    bogus: 1\n    steps: [{run: x}]\n", i)
	}
	_, err := Parse([]byte(b.String()))
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if len(pe.Problems) != maxErrors {
		t.Fatalf("problems = %d, want capped at %d", len(pe.Problems), maxErrors)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"main", "main", true},
		{"main", "mainline", false},
		{"release/*", "release/1.0", true},
		{"release/*", "release/1/0", false},
		{"release/**", "release/1/0", true},
		{"*", "feature/x", false},
		{"**", "feature/x", true},
		{"feat-*-fix", "feat-login-fix", true},
		{"feat-*-fix", "feat-login-fix2", false},
		{"", "", true},
		{"*", "", true},
		{"a*b*c*d*e*f*g*h*i*j", strings.Repeat("a", 5000), false},
	}
	for _, c := range cases {
		if got := Glob(c.pattern, c.name); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestProblem_String(t *testing.T) {
	if s := (Problem{Message: "m"}).String(); s != "m" {
		t.Fatal(s)
	}
	if s := (Problem{Path: "a.b", Line: 3, Message: "m"}).String(); s != "a.b (line 3): m" {
		t.Fatal(s)
	}
}

// FuzzParse: the loader must never panic, hang, or accept a document that
// violates its own invariants.
func FuzzParse(f *testing.F) {
	files, _ := fs.Glob(testdata, "*/*.yaml")
	for _, file := range files {
		if data, err := fs.ReadFile(testdata, file); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pl, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		if len(pl.Jobs) == 0 || len(pl.Jobs) > MaxJobs {
			t.Fatalf("accepted %d jobs", len(pl.Jobs))
		}
		for _, j := range pl.Jobs {
			if j.Image == "" || len(j.Steps) == 0 || j.Timeout < MinJobTimeout || j.Timeout > MaxJobTimeout {
				t.Fatalf("accepted invalid job %+v", j)
			}
			for _, s := range j.Steps {
				if s.Run == "" || strings.Contains(s.Run, "${{") || hasControl(s.Name) {
					t.Fatalf("accepted invalid step %+v", s)
				}
			}
		}
	})
}
