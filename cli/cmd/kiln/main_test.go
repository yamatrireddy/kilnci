// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/cli/internal/client"
	"github.com/yamatrireddy/kilnci/cli/internal/config"
)

// fakeServer answers the lint API: a pipeline containing "bad" is invalid.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kiln_pat_ok" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"title":"Unauthenticated","status":401}`)
			return
		}
		var body struct{ Pipeline string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body.Pipeline, "bad") {
			_, _ = io.WriteString(w, `{"valid":false,"problems":[{"path":"jobs.a","line":3,"message":"bad\u001b[2Jthing"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"valid":true,"problems":[]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type result struct {
	code           int
	stdout, stderr string
}

func invoke(t *testing.T, srv *httptest.Server, vars map[string]string, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	e := env{
		stdin: strings.NewReader(stdin), stdout: &out, stderr: &errOut,
		lookup: func(k string) (string, bool) { v, ok := vars[k]; return v, ok },
	}
	if srv != nil {
		e.clientOpts = client.Options{Transport: srv.Client().Transport}
	}
	code := run(t.Context(), args, e)
	return result{code, out.String(), errOut.String()}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLint(t *testing.T) {
	srv := fakeServer(t)
	dir := t.TempDir()
	good := writeFile(t, dir, "good.yaml", []byte("version: 1\n"))
	bad := writeFile(t, dir, "bad.yaml", []byte("version: 1\nbad\n"))
	tokenFile := writeFile(t, dir, "token", []byte("kiln_pat_ok\n"))
	big := writeFile(t, dir, "big.yaml", bytes.Repeat([]byte("#"), maxPipelineBytes+1))
	latin1 := writeFile(t, dir, "latin1.yaml", []byte("name: caf\xe9\n"))
	vars := map[string]string{config.EnvServer: srv.URL, config.EnvToken: "kiln_pat_ok"}

	tests := []struct {
		name       string
		vars       map[string]string
		stdin      string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "valid", vars: vars, args: []string{"lint", good}, wantCode: exitOK, wantStdout: "pipeline is valid"},
		{name: "invalid", vars: vars, args: []string{"lint", bad}, wantCode: exitInvalid,
			wantStdout: bad + ":3: jobs.a: bad?[2Jthing\n1 problem found"},
		{name: "json", vars: vars, args: []string{"lint", "--format", "json", bad}, wantCode: exitInvalid,
			wantStdout: `"valid": false`},
		{name: "stdin pipeline", vars: vars, stdin: "version: 1\n", args: []string{"lint", "-"}, wantCode: exitOK,
			wantStdout: "<stdin>: pipeline is valid"},
		{name: "token file and server flag", vars: nil,
			args:     []string{"lint", "--server", srv.URL, "--token-file", tokenFile, good},
			wantCode: exitOK, wantStdout: "pipeline is valid"},
		{name: "wrong token", vars: map[string]string{config.EnvServer: srv.URL, config.EnvToken: "kiln_pat_wrong"},
			args: []string{"lint", good}, wantCode: exitError, wantStderr: "kiln: server returned 401"},
		{name: "both from stdin", vars: vars, args: []string{"lint", "--token-file", "-", "-"}, wantCode: exitError,
			wantStderr: "cannot both come from stdin"},
		{name: "no server", vars: map[string]string{config.EnvToken: "kiln_pat_ok"}, args: []string{"lint", good},
			wantCode: exitError, wantStderr: "no server"},
		{name: "bad format", vars: vars, args: []string{"lint", "--format", "xml", good}, wantCode: exitError,
			wantStderr: "unknown format"},
		{name: "two files", vars: vars, args: []string{"lint", good, bad}, wantCode: exitError, wantStderr: "at most one file"},
		{name: "missing file", vars: vars, args: []string{"lint", filepath.Join(dir, "none.yaml")}, wantCode: exitError,
			wantStderr: "open pipeline"},
		{name: "default file missing", vars: vars, args: []string{"lint"}, wantCode: exitError, wantStderr: "pipeline.yaml"},
		{name: "directory", vars: vars, args: []string{"lint", dir}, wantCode: exitError, wantStderr: "not a regular file"},
		{name: "oversized", vars: vars, args: []string{"lint", big}, wantCode: exitError, wantStderr: "exceeds 256 KiB"},
		{name: "not utf-8", vars: vars, args: []string{"lint", latin1}, wantCode: exitError, wantStderr: "not valid UTF-8"},
		{name: "unknown flag", vars: vars, args: []string{"lint", "--token", "kiln_pat_ok", good}, wantCode: exitError},
		{name: "lint help", args: []string{"lint", "-h"}, wantCode: exitOK, wantStderr: "usage:"},
		{name: "no args", wantCode: exitError, wantStderr: "usage:"},
		{name: "unknown command", args: []string{"deploy"}, wantCode: exitError, wantStderr: "usage:"},
		{name: "help", args: []string{"help"}, wantCode: exitOK, wantStdout: "KILN_TOKEN"},
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantStdout: "kiln dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := invoke(t, srv, tt.vars, tt.stdin, tt.args...)
			if r.code != tt.wantCode || !strings.Contains(r.stdout, tt.wantStdout) || !strings.Contains(r.stderr, tt.wantStderr) {
				t.Fatalf("code %d stdout %q stderr %q; want code %d stdout ~%q stderr ~%q",
					r.code, r.stdout, r.stderr, tt.wantCode, tt.wantStdout, tt.wantStderr)
			}
			if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
				t.Fatalf("raw escape reached the terminal: %q", r.stdout+r.stderr)
			}
			if strings.Contains(r.stdout+r.stderr, "kiln_pat_") {
				t.Fatalf("token printed: %q", r.stdout+r.stderr)
			}
		})
	}
}

func TestLint_DefaultPipelinePath(t *testing.T) {
	srv := fakeServer(t)
	dir := t.TempDir()
	writeFile(t, dir, defaultPipeline, []byte("version: 1\n"))
	t.Chdir(dir)
	r := invoke(t, srv, map[string]string{config.EnvServer: srv.URL, config.EnvToken: "kiln_pat_ok"}, "", "lint")
	if r.code != exitOK || !strings.Contains(r.stdout, ".kiln/pipeline.yaml: pipeline is valid") {
		t.Fatalf("%+v", r)
	}
}
