// SPDX-License-Identifier: Apache-2.0

// Command kiln is the Kiln command-line client. This file only wires
// components together.
//
//	kiln lint [--server URL] [--token-file FILE|-] [--format text|json] [FILE|-]
//	kiln version
//
// kiln lint sends a pipeline to POST /api/v1/pipelines/lint, so the CLI and
// the server share one parser (ADR-0008). Exit status: 0 valid, 1 invalid,
// 2 usage or request error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"github.com/yamatrireddy/kilnci/cli/internal/client"
	"github.com/yamatrireddy/kilnci/cli/internal/config"
	"github.com/yamatrireddy/kilnci/cli/internal/output"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit statuses.
const (
	exitOK      = 0
	exitInvalid = 1
	exitError   = 2
)

// defaultPipeline is where a repository keeps its pipeline.
const defaultPipeline = ".kiln/pipeline.yaml"

// maxPipelineBytes matches the server's limit (engine/spec.MaxBytes).
const maxPipelineBytes = 256 << 10

const usage = `usage:
  kiln lint [--server URL] [--token-file FILE|-] [--format text|json] [FILE|-]
  kiln version

environment:
  KILN_SERVER  server URL, like https://kiln.example.com (--server overrides)
  KILN_TOKEN   API token with the pipelines:lint scope (--token-file overrides)

FILE defaults to .kiln/pipeline.yaml; - reads the pipeline from stdin.
Exit status: 0 valid, 1 invalid, 2 usage or request error.`

type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	lookup         config.Lookup
	clientOpts     client.Options // tests inject a transport
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, lookup: config.Environ()})
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, e env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(e.stderr, usage)
		return exitError
	}
	switch args[0] {
	case "lint":
		return lint(ctx, args[1:], e)
	case "version":
		_, _ = fmt.Fprintln(e.stdout, "kiln", version)
		return exitOK
	case "help", "-h", "--help":
		_, _ = fmt.Fprintln(e.stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprintln(e.stderr, usage)
		return exitError
	}
}

func lint(ctx context.Context, args []string, e env) int {
	fl := flag.NewFlagSet("lint", flag.ContinueOnError)
	fl.SetOutput(e.stderr)
	fl.Usage = func() { _, _ = fmt.Fprintln(e.stderr, usage) }
	server := fl.String("server", "", "Kiln server URL (default $KILN_SERVER)")
	credsPath := fl.String("token-file", "", "file holding the API token, or - for stdin (default $KILN_TOKEN; tokens are never taken as arguments)")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if fl.NArg() > 1 {
		return fail(e, errors.New("lint takes at most one file"))
	}
	file := defaultPipeline
	if fl.NArg() == 1 {
		file = fl.Arg(0)
	}
	if file == "-" && *credsPath == "-" {
		return fail(e, errors.New("the pipeline and the token cannot both come from stdin"))
	}
	f, err := output.ParseFormat(*format)
	if err != nil {
		return fail(e, err)
	}
	cfg, err := config.Load(config.Options{Server: *server, TokenFile: *credsPath}, e.lookup, e.stdin)
	if err != nil {
		return fail(e, err)
	}
	source, err := readPipeline(file, e.stdin)
	if err != nil {
		return fail(e, err)
	}
	opts := e.clientOpts
	opts.UserAgent = "kiln-cli/" + version
	c, err := client.New(cfg.Server, cfg.Token, opts)
	if err != nil {
		return fail(e, err)
	}
	res, err := c.Lint(ctx, source)
	if err != nil {
		return fail(e, err)
	}
	name := file
	if name == "-" {
		name = "<stdin>"
	}
	if err := output.Write(e.stdout, f, name, res); err != nil {
		return fail(e, fmt.Errorf("write output: %w", err))
	}
	if !res.Valid {
		return exitInvalid
	}
	return exitOK
}

func fail(e env, err error) int {
	_, _ = fmt.Fprintln(e.stderr, "kiln:", output.Clean(err.Error()))
	return exitError
}

// readPipeline reads at most maxPipelineBytes from path ("-" is stdin) and
// rejects content the server would not accept, so the user gets a local error
// instead of a 413 or a silently altered document.
func readPipeline(path string, stdin io.Reader) (string, error) {
	var r io.Reader
	if path == "-" {
		r = stdin
	} else {
		f, err := os.DirFS(filepath.Dir(path)).Open(filepath.Base(path))
		if err != nil {
			return "", fmt.Errorf("open pipeline: %w", err)
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("stat pipeline: %w", err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a regular file", path)
		}
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxPipelineBytes+1))
	if err != nil {
		return "", fmt.Errorf("read pipeline: %w", err)
	}
	if len(b) > maxPipelineBytes {
		return "", fmt.Errorf("pipeline exceeds %d KiB, the server's limit", maxPipelineBytes>>10)
	}
	if !utf8.Valid(b) {
		return "", errors.New("pipeline is not valid UTF-8")
	}
	return string(b), nil
}
