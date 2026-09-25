// SPDX-License-Identifier: Apache-2.0

package spec

import (
	"strings"
	"time"
)

// Version is the only pipeline format version this parser accepts.
const Version = 1

// Path is where a repository's pipeline lives.
const Path = ".kiln/pipeline.yaml"

// Pipeline is a validated pipeline definition.
type Pipeline struct {
	On   Triggers
	Env  []EnvVar
	Jobs []Job // in document order
}

// Triggers filters which events start a run.
type Triggers struct {
	// Push and PullRequest are nil when that event does not start runs.
	Push        *BranchFilter
	PullRequest *BranchFilter
}

// BranchFilter matches branch names against globs. An empty list matches
// every branch.
type BranchFilter struct {
	Branches []string
}

// Job is one node of the run graph.
type Job struct {
	ID      string
	Image   string
	RunsOn  []string
	Needs   []string
	Timeout time.Duration
	Retries int
	Env     []EnvVar
	Steps   []Step
}

// Step is one script executed in the job container.
type Step struct {
	Name    string
	Run     string
	Env     []EnvVar
	Timeout time.Duration // zero: bounded only by the job timeout
}

// EnvVar is one environment entry. Lists are sorted by name.
type EnvVar struct {
	Name  string
	Value string
}

// Defaults and bounds (docs/specs/pipeline.md).
const (
	DefaultJobTimeout = 60 * time.Minute
	MinJobTimeout     = time.Minute
	MaxJobTimeout     = 24 * time.Hour
	MinStepTimeout    = time.Second
	MaxRetries        = 3
	MaxJobs           = 50
	MaxSteps          = 100
	MaxLabels         = 10
	MaxEnv            = 100
	MaxPatterns       = 50
	MaxRunBytes       = 64 << 10
	MaxEnvValueBytes  = 32 << 10
	MaxImageLen       = 255
	MaxNameRunes      = 100
	MaxPatternLen     = 255
)

// MatchesPush reports whether a push to branch starts a run.
func (t Triggers) MatchesPush(branch string) bool {
	return t.Push != nil && t.Push.matches(branch)
}

// MatchesPullRequest reports whether a pull request into baseBranch starts a run.
func (t Triggers) MatchesPullRequest(baseBranch string) bool {
	return t.PullRequest != nil && t.PullRequest.matches(baseBranch)
}

func (f *BranchFilter) matches(branch string) bool {
	if len(f.Branches) == 0 {
		return true
	}
	for _, p := range f.Branches {
		if Glob(p, branch) {
			return true
		}
	}
	return false
}

// Glob reports whether name matches pattern, where "*" matches any run of
// characters except "/" and "**" matches any run of characters. Every other
// character matches itself. Matching is iterative with memoization, so it is
// O(len(pattern) * len(name)) even for adversarial patterns.
func Glob(pattern, name string) bool {
	// Tokenize: '*' (single), '/'-crossing '**' (double), or a literal byte.
	type tok struct {
		star, double bool
		b            byte
	}
	var toks []tok
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '*' {
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				for i+1 < len(pattern) && pattern[i+1] == '*' {
					i++
				}
				toks = append(toks, tok{star: true, double: true})
				continue
			}
			toks = append(toks, tok{star: true})
			continue
		}
		toks = append(toks, tok{b: pattern[i]})
	}
	// dp[j] = toks[i:] matches name[j:]; computed from the end.
	n := len(name)
	next := make([]bool, n+1)
	next[n] = true // empty pattern matches empty name
	cur := make([]bool, n+1)
	for i := len(toks) - 1; i >= 0; i-- {
		t := toks[i]
		cur[n] = t.star && next[n]
		for j := n - 1; j >= 0; j-- {
			switch {
			case t.star:
				// Match zero chars, or one more char (if allowed) and stay.
				cur[j] = next[j] || ((t.double || name[j] != '/') && cur[j+1])
			default:
				cur[j] = name[j] == t.b && next[j+1]
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

// firstLine returns the first non-empty line of s, trimmed and shortened to
// at most MaxNameRunes runes, for default step names.
func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r := []rune(line)
		if len(r) > MaxNameRunes {
			r = r[:MaxNameRunes]
		}
		return string(r)
	}
	return "step"
}
