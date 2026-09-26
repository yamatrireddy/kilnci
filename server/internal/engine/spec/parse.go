// SPDX-License-Identifier: Apache-2.0

package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/yamatrireddy/kilnci/server/internal/engine/dag"
)

// Safe-loader limits (threat T-07).
const (
	MaxBytes = 256 << 10
	MaxDepth = 20
	MaxNodes = 20000
	// maxErrors caps how many problems one Parse reports.
	maxErrors = 50
)

var (
	jobIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	labelPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// imagePattern is a conservative image reference: registry/path[:tag][@digest].
	imagePattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
	lineInError  = regexp.MustCompile(`line (\d+)`)
	// safeKeyPattern: keys that may appear in error paths.
	safeKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ErrInvalid wraps every parse failure, so callers can use errors.Is.
var ErrInvalid = errors.New("invalid pipeline")

// Problem is one validation failure. Path is a dotted field path
// ("jobs.test.steps[0].run"), Line is 1-based (0 if unknown), and Message is
// safe to show: it never contains field values from the document.
type Problem struct {
	Path    string
	Line    int
	Message string
}

// String formats the problem for display.
func (p Problem) String() string {
	loc := p.Path
	if p.Line > 0 {
		loc += fmt.Sprintf(" (line %d)", p.Line)
	}
	if loc == "" {
		return p.Message
	}
	return loc + ": " + p.Message
}

// Error lists every problem found in a pipeline.
type Error struct {
	Problems []Problem
}

// Error implements error.
func (e *Error) Error() string {
	parts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		parts[i] = p.String()
	}
	return "invalid pipeline: " + strings.Join(parts, "; ")
}

// Unwrap makes errors.Is(err, ErrInvalid) true.
func (e *Error) Unwrap() error { return ErrInvalid }

// Parse validates data as a version 1 pipeline. It returns *Error (wrapping
// ErrInvalid) listing the problems when the document is not acceptable.
func Parse(data []byte) (*Pipeline, error) {
	p := &parser{}
	pl := p.parse(data)
	if len(p.problems) > 0 {
		return nil, &Error{Problems: p.problems}
	}
	return pl, nil
}

type parser struct {
	problems []Problem
}

func (p *parser) fail(path string, n *yaml.Node, msg string) {
	if len(p.problems) >= maxErrors {
		return
	}
	line := 0
	if n != nil {
		line = n.Line
	}
	p.problems = append(p.problems, Problem{Path: path, Line: line, Message: msg})
}

func (p *parser) parse(data []byte) *Pipeline {
	if len(data) > MaxBytes {
		p.fail("", nil, fmt.Sprintf("document exceeds %d KiB", MaxBytes>>10))
		return nil
	}
	if !utf8.Valid(data) {
		p.fail("", nil, "document must be valid UTF-8")
		return nil
	}
	if bytes.IndexByte(data, 0) >= 0 {
		p.fail("", nil, "document must not contain NUL bytes")
		return nil
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			p.fail("", nil, "document is empty")
		} else {
			p.syntaxError(err)
		}
		return nil
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		p.fail("", nil, "only one YAML document is allowed")
		return nil
	}
	if !p.checkStructure(&doc) {
		return nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		p.fail("", nil, "document is empty")
		return nil
	}
	return p.pipeline(doc.Content[0])
}

// syntaxError reports a YAML syntax error by line only; library messages can
// quote document content.
func (p *parser) syntaxError(err error) {
	line := 0
	if m := lineInError.FindStringSubmatch(err.Error()); m != nil {
		line, _ = strconv.Atoi(m[1])
	}
	p.problems = append(p.problems, Problem{Line: line, Message: "invalid YAML syntax"})
}

// checkStructure enforces the structural limits on the whole tree before any
// interpretation: depth, node count, no anchors/aliases/merge keys, no
// explicit tags, and no expression syntax anywhere.
func (p *parser) checkStructure(root *yaml.Node) bool {
	count := 0
	ok := true
	var walk func(n *yaml.Node, depth int)
	walk = func(n *yaml.Node, depth int) {
		if !ok {
			return
		}
		count++
		switch {
		case count > MaxNodes:
			p.fail("", n, fmt.Sprintf("document has more than %d nodes", MaxNodes))
			ok = false
			return
		case depth > MaxDepth:
			p.fail("", n, fmt.Sprintf("document is nested deeper than %d levels", MaxDepth))
			ok = false
			return
		case n.Kind == yaml.AliasNode || n.Anchor != "":
			p.fail("", n, "anchors and aliases are not allowed")
			ok = false
			return
		case n.Style&yaml.TaggedStyle != 0:
			p.fail("", n, "explicit YAML tags are not allowed")
			ok = false
			return
		case n.Kind == yaml.ScalarNode && strings.Contains(n.Value, "${{"):
			p.fail("", n, "expressions (${{ ... }}) are not supported; use KILN_* environment variables")
			ok = false
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i]; k.Kind == yaml.ScalarNode && k.Value == "<<" && k.Style == 0 {
					p.fail("", k, "merge keys (<<) are not allowed")
					ok = false
					return
				}
			}
		}
		for _, c := range n.Content {
			walk(c, depth+1)
		}
	}
	walk(root, 0)
	return ok
}

// fieldFn handles one known mapping key.
type fieldFn func(path string, key, val *yaml.Node)

// mapping walks a mapping node, dispatching known keys, rejecting unknown and
// duplicate keys, and reporting missing required keys.
func (p *parser) mapping(path string, n *yaml.Node, fields map[string]fieldFn, required ...string) {
	if n.Kind != yaml.MappingNode {
		p.fail(path, n, "must be a mapping")
		return
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			p.fail(path, k, "keys must be plain strings")
			continue
		}
		child := join(path, k.Value)
		if seen[k.Value] {
			p.fail(child, k, "is defined more than once")
			continue
		}
		seen[k.Value] = true
		fn, ok := fields[k.Value]
		if !ok {
			p.fail(child, k, "is not a known field")
			continue
		}
		fn(child, k, v)
	}
	for _, r := range required {
		if !seen[r] {
			p.fail(join(path, r), n, "is required")
		}
	}
}

// join appends key to a dotted path. Keys that are not short, plain
// identifiers are shown as "?" so error messages never carry arbitrary
// document content.
func join(path, key string) string {
	if !safeKeyPattern.MatchString(key) {
		key = "?"
	}
	if path == "" {
		return key
	}
	return path + "." + key
}

// scalar returns a non-null scalar's text.
func (p *parser) scalar(path string, n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() == "!!null" {
		p.fail(path, n, "must be a value")
		return "", false
	}
	return n.Value, true
}

func (p *parser) str(path string, n *yaml.Node) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		p.fail(path, n, "must be a string")
		return "", false
	}
	return n.Value, true
}

func (p *parser) integer(path string, n *yaml.Node, lo, hi int) (int, bool) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" {
		p.fail(path, n, "must be an integer")
		return 0, false
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil || v < lo || v > hi {
		p.fail(path, n, fmt.Sprintf("must be between %d and %d", lo, hi))
		return 0, false
	}
	return v, true
}

func (p *parser) duration(path string, n *yaml.Node, lo, hi time.Duration) (time.Duration, bool) {
	s, ok := p.str(path, n)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		p.fail(path, n, "must be a duration such as 90s, 20m, or 2h")
		return 0, false
	}
	if d < lo || d > hi {
		p.fail(path, n, fmt.Sprintf("must be between %s and %s", lo, hi))
		return 0, false
	}
	return d, true
}

// list returns a sequence's items (at most maxItems).
func (p *parser) list(path string, n *yaml.Node, maxItems int) ([]*yaml.Node, bool) {
	if n.Kind != yaml.SequenceNode {
		p.fail(path, n, "must be a list")
		return nil, false
	}
	if len(n.Content) > maxItems {
		p.fail(path, n, fmt.Sprintf("must have at most %d items", maxItems))
		return nil, false
	}
	return n.Content, true
}

// strings parses a list of strings, each checked by valid.
func (p *parser) strList(path string, n *yaml.Node, maxItems int, valid func(string) bool, rule string) []string {
	items, ok := p.list(path, n, maxItems)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for i, it := range items {
		ip := fmt.Sprintf("%s[%d]", path, i)
		s, ok := p.str(ip, it)
		if !ok {
			continue
		}
		if !valid(s) {
			p.fail(ip, it, rule)
			continue
		}
		if seen[s] {
			p.fail(ip, it, "is listed more than once")
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func (p *parser) env(path string, n *yaml.Node) []EnvVar {
	if n.Kind != yaml.MappingNode {
		p.fail(path, n, "must be a mapping")
		return nil
	}
	if len(n.Content)/2 > MaxEnv {
		p.fail(path, n, fmt.Sprintf("must have at most %d entries", MaxEnv))
		return nil
	}
	var out []EnvVar
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			p.fail(path, k, "keys must be plain strings")
			continue
		}
		child := join(path, k.Value)
		if !envKeyPattern.MatchString(k.Value) {
			p.fail(path, k, "has a key that is not a valid environment variable name")
			continue
		}
		if strings.HasPrefix(strings.ToUpper(k.Value), "KILN_") {
			p.fail(child, k, "uses the reserved KILN_ prefix")
			continue
		}
		if seen[k.Value] {
			p.fail(child, k, "is defined more than once")
			continue
		}
		seen[k.Value] = true
		val, ok := p.scalar(child, v)
		if !ok {
			continue
		}
		if len(val) > MaxEnvValueBytes {
			p.fail(child, v, fmt.Sprintf("must be at most %d KiB", MaxEnvValueBytes>>10))
			continue
		}
		out = append(out, EnvVar{Name: k.Value, Value: val})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (p *parser) pipeline(root *yaml.Node) *Pipeline {
	pl := &Pipeline{On: Triggers{Push: &BranchFilter{}, PullRequest: &BranchFilter{}}}
	var jobsNode *yaml.Node
	p.mapping("", root, map[string]fieldFn{
		"version": func(path string, _, v *yaml.Node) {
			if v.Kind != yaml.ScalarNode || v.ShortTag() != "!!int" || v.Value != strconv.Itoa(Version) {
				p.fail(path, v, fmt.Sprintf("must be %d", Version))
			}
		},
		"on":   func(path string, _, v *yaml.Node) { pl.On = p.triggers(path, v) },
		"env":  func(path string, _, v *yaml.Node) { pl.Env = p.env(path, v) },
		"jobs": func(_ string, _, v *yaml.Node) { jobsNode = v },
	}, "version", "jobs")
	if jobsNode != nil {
		pl.Jobs = p.jobs("jobs", jobsNode)
	}
	if len(p.problems) > 0 {
		return nil
	}
	nodes := make([]dag.Node, len(pl.Jobs))
	for i, j := range pl.Jobs {
		nodes[i] = dag.Node{ID: j.ID, Needs: j.Needs}
	}
	if _, err := dag.Plan(nodes); err != nil {
		var ge *dag.GraphError
		if errors.As(err, &ge) {
			p.fail(join("jobs", ge.Node)+".needs", jobsNode, ge.Message)
		} else {
			p.fail("jobs", jobsNode, "has an invalid dependency graph")
		}
		return nil
	}
	return pl
}

func (p *parser) triggers(path string, n *yaml.Node) Triggers {
	var t Triggers
	filter := func(path string, v *yaml.Node) *BranchFilter {
		f := &BranchFilter{}
		if v.Kind == yaml.ScalarNode && v.ShortTag() == "!!null" {
			return f // "push:" with no body: every branch
		}
		p.mapping(path, v, map[string]fieldFn{
			"branches": func(path string, _, v *yaml.Node) {
				f.Branches = p.strList(path, v, MaxPatterns, func(s string) bool {
					return s != "" && len(s) <= MaxPatternLen && !hasControl(s)
				}, fmt.Sprintf("must be a branch pattern of 1-%d characters", MaxPatternLen))
			},
		})
		return f
	}
	p.mapping(path, n, map[string]fieldFn{
		"push":         func(path string, _, v *yaml.Node) { t.Push = filter(path, v) },
		"pull_request": func(path string, _, v *yaml.Node) { t.PullRequest = filter(path, v) },
	})
	return t
}

func (p *parser) jobs(path string, n *yaml.Node) []Job {
	if n.Kind != yaml.MappingNode {
		p.fail(path, n, "must be a mapping of job IDs to jobs")
		return nil
	}
	count := len(n.Content) / 2
	if count == 0 || count > MaxJobs {
		p.fail(path, n, fmt.Sprintf("must define 1-%d jobs", MaxJobs))
		return nil
	}
	var out []Job
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || !jobIDPattern.MatchString(k.Value) {
			p.fail(path, k, "job IDs must match ^[a-z][a-z0-9_-]{0,62}$")
			continue
		}
		if seen[k.Value] {
			p.fail(join(path, k.Value), k, "is defined more than once")
			continue
		}
		seen[k.Value] = true
		out = append(out, p.job(join(path, k.Value), k.Value, v))
	}
	return out
}

func (p *parser) job(path, id string, n *yaml.Node) Job {
	j := Job{ID: id, Timeout: DefaultJobTimeout}
	var stepsNode *yaml.Node
	p.mapping(path, n, map[string]fieldFn{
		"image": func(path string, _, v *yaml.Node) {
			if s, ok := p.str(path, v); ok {
				if len(s) > MaxImageLen || !imagePattern.MatchString(s) {
					p.fail(path, v, "must be a container image reference (name[:tag][@sha256:digest])")
					return
				}
				j.Image = s
			}
		},
		"runs-on": func(path string, _, v *yaml.Node) {
			j.RunsOn = p.strList(path, v, MaxLabels, labelPattern.MatchString, "must be a runner label matching ^[a-z0-9][a-z0-9._-]{0,62}$")
			slices.Sort(j.RunsOn)
		},
		"needs": func(path string, _, v *yaml.Node) {
			j.Needs = p.strList(path, v, MaxJobs, jobIDPattern.MatchString, "must be a job ID")
		},
		"timeout": func(path string, _, v *yaml.Node) {
			if d, ok := p.duration(path, v, MinJobTimeout, MaxJobTimeout); ok {
				j.Timeout = d
			}
		},
		"retries": func(path string, _, v *yaml.Node) {
			if r, ok := p.integer(path, v, 0, MaxRetries); ok {
				j.Retries = r
			}
		},
		"env":   func(path string, _, v *yaml.Node) { j.Env = p.env(path, v) },
		"steps": func(_ string, _, v *yaml.Node) { stepsNode = v },
	}, "image", "steps")
	if stepsNode != nil {
		j.Steps = p.steps(join(path, "steps"), stepsNode, j.Timeout)
	}
	return j
}

func (p *parser) steps(path string, n *yaml.Node, jobTimeout time.Duration) []Step {
	items, ok := p.list(path, n, MaxSteps)
	if !ok {
		return nil
	}
	if len(items) == 0 {
		p.fail(path, n, fmt.Sprintf("must have 1-%d steps", MaxSteps))
		return nil
	}
	out := make([]Step, 0, len(items))
	for i, it := range items {
		sp := fmt.Sprintf("%s[%d]", path, i)
		var st Step
		p.mapping(sp, it, map[string]fieldFn{
			"name": func(path string, _, v *yaml.Node) {
				s, ok := p.scalar(path, v)
				if !ok {
					return
				}
				if s = strings.TrimSpace(s); s == "" || utf8.RuneCountInString(s) > MaxNameRunes || hasControl(s) {
					p.fail(path, v, fmt.Sprintf("must be 1-%d characters without control characters", MaxNameRunes))
					return
				}
				st.Name = s
			},
			"run": func(path string, _, v *yaml.Node) {
				s, ok := p.str(path, v)
				if !ok {
					return
				}
				if strings.TrimSpace(s) == "" || len(s) > MaxRunBytes {
					p.fail(path, v, fmt.Sprintf("must be a non-empty script of at most %d KiB", MaxRunBytes>>10))
					return
				}
				st.Run = s
			},
			"env": func(path string, _, v *yaml.Node) { st.Env = p.env(path, v) },
			"timeout": func(path string, _, v *yaml.Node) {
				if d, ok := p.duration(path, v, MinStepTimeout, jobTimeout); ok {
					st.Timeout = d
				}
			},
		}, "run")
		if st.Name == "" {
			st.Name = sanitizeName(firstLine(st.Run))
		}
		out = append(out, st)
	}
	return out
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, isUnsafeRune)
}

// isUnsafeRune reports control characters and invisible format characters
// (bidi overrides, zero-width characters, line separators) that could make
// a name display differently from what it says.
func isUnsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

// sanitizeName replaces control characters (e.g. ANSI escapes in a script's
// first line) so derived names are safe to display.
func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		if isUnsafeRune(r) {
			return '?'
		}
		return r
	}, s)
}
