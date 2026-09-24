// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		slug string
		ok   bool
	}{
		{"a", true},
		{"acme", true},
		{"acme-corp", true},
		{"a1-b2-c3", true},
		{strings.Repeat("a", 40), true},
		{strings.Repeat("a", 41), false},
		{"", false},
		{"-acme", false},
		{"acme-", false},
		{"ac--me", false},
		{"Acme", false},
		{"acme_corp", false},
		{"acme.corp", false},
		{"../etc", false},
		{"acme\n", false},
		{"ác", false},
	}
	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			err := ValidateSlug("slug", tt.slug)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateSlug(%q) err=%v, want ok=%v", tt.slug, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrValidation) {
				t.Fatalf("error does not unwrap to ErrValidation: %v", err)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"  Acme Corp ", "Acme Corp", true},
		{"日本語の名前", "日本語の名前", true},
		{strings.Repeat("é", 100), strings.Repeat("é", 100), true},
		{strings.Repeat("é", 101), "", false},
		{"   ", "", false},
		{"bad\x00name", "", false},
		{"bad\x1bname", "", false},
		{"bad\x7fname", "", false},
	}
	for _, tt := range tests {
		got, err := NormalizeName("name", tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q, ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestValidationError(t *testing.T) {
	var ve *ValidationError
	if ve.OrNil() != nil {
		t.Fatal("nil ValidationError should be OrNil() == nil")
	}
	if (&ValidationError{}).OrNil() != nil {
		t.Fatal("empty ValidationError should be OrNil() == nil")
	}
	two := NewValidationError("a", "bad")
	two.Add("b", "worse")
	err := two.OrNil()
	if !errors.Is(err, ErrValidation) {
		t.Fatal("want errors.Is ErrValidation")
	}
	if got := err.Error(); got != "validation failed: a: bad; b: worse" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestRole_AtLeast(t *testing.T) {
	tests := []struct {
		r, minRole Role
		want       bool
	}{
		{RoleOwner, RoleViewer, true},
		{RoleAdmin, RoleAdmin, true},
		{RoleDeveloper, RoleAdmin, false},
		{RoleViewer, RoleDeveloper, false},
		{Role("superuser"), RoleViewer, false},
		{RoleOwner, Role("bogus"), false},
		{Role(""), Role(""), false},
	}
	for _, tt := range tests {
		if got := tt.r.AtLeast(tt.minRole); got != tt.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", tt.r, tt.minRole, got, tt.want)
		}
	}
	if Role("x").Valid() || !RoleOwner.Valid() {
		t.Fatal("Valid() wrong")
	}
}
