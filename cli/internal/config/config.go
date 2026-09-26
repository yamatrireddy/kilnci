// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Environment variables the CLI reads.
const (
	EnvServer = "KILN_SERVER"
	EnvToken  = "KILN_TOKEN"
)

// maxTokenBytes bounds a token read from a file or stdin. Kiln tokens are far
// shorter; the cap only stops a mistaken path from being read whole.
const maxTokenBytes = 4 << 10

// Lookup reads one environment variable, like os.LookupEnv.
type Lookup func(key string) (string, bool)

// Environ returns the process environment as a Lookup.
func Environ() Lookup { return os.LookupEnv }

// Config is the resolved configuration for one API call.
type Config struct {
	// Server is the base URL of the Kiln server, without a trailing slash.
	Server *url.URL
	// Token is the bearer token (a personal API token or desktop access token).
	Token string
}

// Options are the raw settings from the command line.
type Options struct {
	// Server overrides KILN_SERVER when set.
	Server string
	// TokenFile names a file holding the token, or "-" for stdin. When set it
	// overrides KILN_TOKEN. There is deliberately no flag that takes the token
	// itself: command lines are visible to other local users and shell history.
	TokenFile string
}

// Load resolves the server URL and token from opts and env.
func Load(opts Options, env Lookup, stdin io.Reader) (Config, error) {
	raw := opts.Server
	if raw == "" {
		raw, _ = env(EnvServer)
	}
	if raw == "" {
		return Config{}, fmt.Errorf("no server: pass --server or set %s", EnvServer)
	}
	server, err := ParseServer(raw)
	if err != nil {
		return Config{}, err
	}
	var token string
	if opts.TokenFile != "" {
		b, err := readToken(opts.TokenFile, stdin)
		if err != nil {
			return Config{}, err
		}
		token = string(b)
	} else {
		token, _ = env(EnvToken)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return Config{}, fmt.Errorf("no token: pass --token-file or set %s", EnvToken)
	}
	if !validToken(token) {
		return Config{}, errors.New("token contains characters that cannot appear in a Kiln token")
	}
	return Config{Server: server, Token: token}, nil
}

// ParseServer validates a Kiln server base URL. It must be https, except that
// plain http is accepted for loopback hosts so a local development server
// works; a bearer token is never sent in clear text over a network. User
// info, queries, and fragments are rejected because they would leak into
// logs or change which endpoint is called.
func ParseServer(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("server URL is not a valid URL")
	}
	switch {
	case u.Host == "" || u.Opaque != "":
		return nil, errors.New("server URL must be absolute, like https://kiln.example.com")
	case u.User != nil:
		return nil, errors.New("server URL must not contain credentials; use --token-file or " + EnvToken)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, errors.New("server URL must not have a query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("server URL must use https (http is allowed only for localhost)")
		}
	default:
		return nil, errors.New("server URL must use https")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validToken accepts visible ASCII only, which also rules out header
// injection through CR or LF.
func validToken(t string) bool {
	for i := range len(t) {
		if t[i] <= ' ' || t[i] > '~' {
			return false
		}
	}
	return true
}

func readToken(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		// A token typed or pasted at a terminal is echoed, and can end up
		// in scrollback or a screen recording.
		if isTerminal(stdin) {
			return nil, errors.New("refusing to read the token from a terminal; pipe it in or use a file")
		}
		r = stdin
	} else {
		f, err := os.DirFS(filepath.Dir(path)).Open(filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("token file is not a regular file")
		}
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxTokenBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	if len(b) > maxTokenBytes {
		return nil, fmt.Errorf("token input exceeds %d bytes", maxTokenBytes)
	}
	return b, nil
}

// isTerminal reports whether r is a character device such as a TTY.
func isTerminal(r io.Reader) bool {
	f, ok := r.(interface{ Stat() (fs.FileInfo, error) })
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&fs.ModeCharDevice != 0
}
