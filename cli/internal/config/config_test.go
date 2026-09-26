// SPDX-License-Identifier: Apache-2.0

package config

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseServer(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr string
	}{
		{raw: "https://kiln.example.com", want: "https://kiln.example.com"},
		{raw: " https://kiln.example.com/ ", want: "https://kiln.example.com"},
		{raw: "https://kiln.example.com/kiln/", want: "https://kiln.example.com/kiln"},
		{raw: "https://kiln.example.com:8443", want: "https://kiln.example.com:8443"},
		{raw: "http://localhost:8080", want: "http://localhost:8080"},
		{raw: "http://LOCALHOST:8080", want: "http://LOCALHOST:8080"},
		{raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{raw: "http://[::1]:8080", want: "http://[::1]:8080"},
		{raw: "http://kiln.example.com", wantErr: "must use https"},
		{raw: "http://10.0.0.5", wantErr: "must use https"},
		{raw: "http://localhost.example.com", wantErr: "must use https"},
		{raw: "ftp://kiln.example.com", wantErr: "must use https"},
		{raw: "https://user:pass@kiln.example.com", wantErr: "must not contain credentials"},
		{raw: "https://kiln.example.com/?x=1", wantErr: "query or fragment"},
		{raw: "https://kiln.example.com/?", wantErr: "query or fragment"},
		{raw: "https://kiln.example.com/#x", wantErr: "query or fragment"},
		{raw: "kiln.example.com", wantErr: "must be absolute"},
		{raw: "https:opaque", wantErr: "must be absolute"},
		{raw: "https://kiln.example.com/%zz", wantErr: "not a valid URL"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := ParseServer(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "pass") && strings.Contains(tt.raw, "pass@") {
					t.Fatalf("error echoes credentials: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.String() != tt.want {
				t.Fatalf("got %q, want %q", u.String(), tt.want)
			}
		})
	}
}

func envOf(m map[string]string) Lookup {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("kiln_pat_fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bigFile := filepath.Join(dir, "big")
	if err := os.WriteFile(bigFile, []byte(strings.Repeat("a", maxTokenBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envOf(map[string]string{EnvServer: "https://env.example.com", EnvToken: " kiln_pat_fromenv "})
	tests := []struct {
		name       string
		opts       Options
		env        Lookup
		stdin      string
		wantServer string
		wantToken  string
		wantErr    string
	}{
		{name: "environment", env: env, wantServer: "https://env.example.com", wantToken: "kiln_pat_fromenv"},
		{name: "flag overrides env server", opts: Options{Server: "https://flag.example.com"}, env: env,
			wantServer: "https://flag.example.com", wantToken: "kiln_pat_fromenv"},
		{name: "token file overrides env", opts: Options{TokenFile: tokenFile}, env: env,
			wantServer: "https://env.example.com", wantToken: "kiln_pat_fromfile"},
		{name: "token from stdin", opts: Options{TokenFile: "-"}, env: env, stdin: "kiln_pat_stdin\n",
			wantServer: "https://env.example.com", wantToken: "kiln_pat_stdin"},
		{name: "no server", env: envOf(map[string]string{EnvToken: "t"}), wantErr: "no server"},
		{name: "bad server", opts: Options{Server: "http://example.com"}, env: env, wantErr: "https"},
		{name: "no token", env: envOf(map[string]string{EnvServer: "https://x.example.com"}), wantErr: "no token"},
		{name: "blank token", env: envOf(map[string]string{EnvServer: "https://x.example.com", EnvToken: "  "}), wantErr: "no token"},
		{name: "empty stdin token", opts: Options{TokenFile: "-"}, env: env, wantErr: "no token"},
		{name: "token with inner newline", opts: Options{TokenFile: "-"}, env: env, stdin: "kiln_pat_a\r\nX-Evil: 1",
			wantErr: "cannot appear"},
		{name: "non-ascii token", env: envOf(map[string]string{EnvServer: "https://x.example.com", EnvToken: "kiln_pat_é"}),
			wantErr: "cannot appear"},
		{name: "missing token file", opts: Options{TokenFile: filepath.Join(dir, "nope")}, env: env, wantErr: "read token file"},
		{name: "oversized token file", opts: Options{TokenFile: bigFile}, env: env, wantErr: "exceeds"},
		{name: "token file is a directory", opts: Options{TokenFile: dir}, env: env, wantErr: "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.opts, tt.env, strings.NewReader(tt.stdin))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "kiln_pat_") {
					t.Fatalf("error leaks the token: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Server.String() != tt.wantServer || cfg.Token != tt.wantToken {
				t.Fatalf("got %s %q, want %s %q", cfg.Server, cfg.Token, tt.wantServer, tt.wantToken)
			}
		})
	}
}

func TestEnviron(t *testing.T) {
	t.Setenv(EnvServer, "https://set.example.com")
	if v, ok := Environ()(EnvServer); !ok || v != "https://set.example.com" {
		t.Fatalf("Environ() = %q %v", v, ok)
	}
}

type ttyStdin struct{ io.Reader }

type charDevice struct{ fs.FileInfo }

func (charDevice) Mode() fs.FileMode { return fs.ModeDevice | fs.ModeCharDevice }

func (ttyStdin) Stat() (fs.FileInfo, error) { return charDevice{}, nil }

func TestLoad_RefusesTokenFromTerminal(t *testing.T) {
	env := envOf(map[string]string{EnvServer: "https://x.example.com"})
	_, err := Load(Options{TokenFile: "-"}, env, ttyStdin{strings.NewReader("kiln_pat_x\n")})
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("err = %v", err)
	}
}
