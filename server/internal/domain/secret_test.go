// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSecretName(t *testing.T) {
	for _, ok := range []string{"TOKEN", "_x", "a1_B2", strings.Repeat("A", 128), "PATHS", "CIRCLE", "KILNX"} {
		if err := ValidateSecretName("n", ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "A B", strings.Repeat("A", 129), "PATH", "path", "HOME", "IFS", "BASH_ENV", "CI",
		"KILN_X", "kiln_x", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "GIT_SSH_COMMAND", "SSH_AUTH_SOCK"} {
		if err := ValidateSecretName("n", bad); !errors.Is(err, ErrValidation) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateSecretValue(t *testing.T) {
	for v, wantMasked := range map[string]bool{"a": false, "abc": false, "abcd": true, strings.Repeat("x", MaxSecretValueBytes): true, "héé": true} {
		masked, err := ValidateSecretValue("value", v)
		if err != nil || masked != wantMasked {
			t.Errorf("len %d: masked=%v err=%v", len(v), masked, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", MaxSecretValueBytes+1), "a\x00bcd", "\xff\xfe\xfd\xfc"} {
		_, err := ValidateSecretValue("value", bad)
		if !errors.Is(err, ErrValidation) {
			t.Errorf("len %d accepted", len(bad))
			continue
		}
		if len(bad) > 0 && strings.Contains(err.Error(), bad) {
			t.Error("error echoes the value")
		}
	}
}

func TestValidateSecretBranches(t *testing.T) {
	if err := ValidateSecretBranches("b", []string{"main", "release/*", "*", "feature/x.y", "v1.2"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		{"ma*n"}, {"*/x"}, {"release/**"}, {"/main"}, {"main/"}, {"a..b"}, {"a//b"}, {"-x"}, {"x.lock"}, {"a b"},
		{"a~b"}, {"a^b"}, {"a:b"}, {"a?b"}, {"a[b"}, {`a\b`}, {"a@{b"}, {"refs/heads/main"}, {"/*"}, {""},
		{"main", "main"}, {strings.Repeat("a", 201)},
	} {
		if err := ValidateSecretBranches("b", bad); !errors.Is(err, ErrValidation) {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, MaxSecretBranchPatterns+1)
	for i := range many {
		many[i] = "b" + strings.Repeat("x", i)
	}
	if err := ValidateSecretBranches("b", many); err == nil {
		t.Error("21 patterns accepted")
	}
}

func TestSecretBranchMatches(t *testing.T) {
	for _, tc := range []struct {
		patterns []string
		branch   string
		want     bool
	}{
		{nil, "anything", true},
		{[]string{"main"}, "main", true},
		{[]string{"main"}, "main2", false},
		{[]string{"main"}, "feature/main", false},
		{[]string{"*"}, "x/y", true},
		{[]string{"release/*"}, "release/1.2", true},
		{[]string{"release/*"}, "release/1/2", true},
		{[]string{"release/*"}, "release/", false},
		{[]string{"release/*"}, "release", false},
		{[]string{"release/*"}, "releases/1", false},
		{[]string{"release/*"}, "x/release/1", false},
		{[]string{"main", "release/*"}, "release/9", true},
	} {
		if got := SecretBranchMatches(tc.patterns, tc.branch); got != tc.want {
			t.Errorf("SecretBranchMatches(%q, %q) = %v, want %v", tc.patterns, tc.branch, got, tc.want)
		}
	}
}

func TestSecret_Scope(t *testing.T) {
	if (Secret{}).Scope() != SecretScopeOrg || (Secret{ProjectID: "p"}).Scope() != SecretScopeProject {
		t.Fatal("scope")
	}
}
