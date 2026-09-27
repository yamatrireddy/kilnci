// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Secret limits (ADR-0009 §3-§4). Value limits match what the runner
// enforces before masking.
const (
	MaxSecretValueBytes     = 64 << 10
	MaxSecretsPerScope      = 500
	MaxSecretBranchPatterns = 20
	MaxSecretProjects       = 100
	// MinMaskedSecretBytes is the shortest value the runner masks; shorter
	// values are accepted with a warning (maintainer decision, 2026-09-27).
	MinMaskedSecretBytes = 4
	maxBranchPatternLen  = 200
)

// SecretScope says whether a secret belongs to an org or a project.
type SecretScope string

// Secret scopes.
const (
	SecretScopeOrg     SecretScope = "org"
	SecretScopeProject SecretScope = "project"
)

// Secret is a secret's metadata. The value is never part of it: it is
// write-only and only the lease builder ever decrypts it.
type Secret struct {
	ID        string
	OrgID     string
	ProjectID string // empty for org secrets
	Name      string
	// ValueVersion increases on every write; it is part of the ciphertext's
	// additional data and serves as the ETag.
	ValueVersion int64
	// Masked is false for values shorter than MinMaskedSecretBytes, which
	// the runner cannot mask.
	Masked bool
	// Branches narrow delivery to matching protected branches.
	Branches []string
	// AllowUnprotected widens delivery to every trusted run of the scope.
	AllowUnprotected bool
	// AllProjects and ProjectIDs say which projects may use an org secret.
	AllProjects bool
	ProjectIDs  []string
	CreatedBy   string
	UpdatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Scope returns the secret's scope.
func (s Secret) Scope() SecretScope {
	if s.ProjectID == "" {
		return SecretScopeOrg
	}
	return SecretScopeProject
}

var secretNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// reservedSecretNames change how the shell, the dynamic loader, git, or ssh
// behave, so a secret must not set them (ADR-0009 §3).
var reservedSecretNames = map[string]bool{
	"PATH": true, "HOME": true, "SHELL": true, "IFS": true, "ENV": true, "BASH_ENV": true,
	"CDPATH": true, "PS4": true, "CI": true,
}

var reservedSecretPrefixes = []string{"KILN_", "LD_", "DYLD_", "GIT_", "SSH_"}

// ValidateSecretName checks a secret name against the environment-variable
// rules of the pipeline spec and the reserved names.
func ValidateSecretName(field, name string) error {
	if !secretNamePattern.MatchString(name) {
		return NewValidationError(field, "must start with a letter or underscore and contain only letters, digits, and underscores (at most 128)")
	}
	upper := strings.ToUpper(name)
	if reservedSecretNames[upper] {
		return NewValidationError(field, "is reserved because it changes how the shell or loader behaves")
	}
	for _, p := range reservedSecretPrefixes {
		if strings.HasPrefix(upper, p) {
			return NewValidationError(field, "uses a reserved prefix ("+strings.Join(reservedSecretPrefixes, ", ")+")")
		}
	}
	return nil
}

// ValidateSecretValue checks a value's size and encoding. It reports whether
// the value is long enough for the runner to mask; the message never echoes
// the value.
func ValidateSecretValue(field, value string) (masked bool, err error) {
	switch {
	case value == "":
		return false, NewValidationError(field, "must not be empty")
	case len(value) > MaxSecretValueBytes:
		return false, NewValidationError(field, "must be at most 64 KiB")
	case !utf8.ValidString(value):
		return false, NewValidationError(field, "must be valid UTF-8")
	case strings.ContainsRune(value, 0):
		return false, NewValidationError(field, "must not contain NUL bytes")
	}
	return len(value) >= MinMaskedSecretBytes, nil
}

// ValidateSecretBranches checks branch patterns: exact branch names, "*",
// or a prefix ending in "/*".
func ValidateSecretBranches(field string, patterns []string) error {
	if len(patterns) > MaxSecretBranchPatterns {
		return NewValidationError(field, "at most 20 patterns")
	}
	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		if seen[p] {
			return NewValidationError(field, "contains a duplicate pattern")
		}
		seen[p] = true
		if !validBranchPattern(p) {
			return NewValidationError(field, "each pattern must be a branch name, \"*\", or a prefix ending in \"/*\"")
		}
	}
	return nil
}

func validBranchPattern(p string) bool {
	if p == "*" {
		return true
	}
	name := p
	if prefix, ok := strings.CutSuffix(p, "/*"); ok {
		name = prefix
	}
	if name == "" || len(p) > maxBranchPatternLen || strings.Contains(name, "*") {
		return false
	}
	// A subset of git's ref-name rules; enough to reject nonsense.
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".lock") ||
		strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasPrefix(name, "-") ||
		strings.Contains(name, "@{") || strings.HasPrefix(name, "refs/") {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`~^:?[\`, r) {
			return false
		}
	}
	return true
}

// SecretBranchMatches reports whether branch matches any pattern. An empty
// list matches every branch. It does not decide protection: callers must
// also require a protected branch unless the secret allows unprotected runs.
func SecretBranchMatches(patterns []string, branch string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, "/*"):
			if strings.HasPrefix(branch, strings.TrimSuffix(p, "*")) && len(branch) > len(p)-1 {
				return true
			}
		case p == branch:
			return true
		}
	}
	return false
}
