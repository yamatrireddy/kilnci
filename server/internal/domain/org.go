// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// slugPattern: lowercase alphanumerics and single hyphens, 1-40 chars, no
// leading/trailing hyphen. Slugs appear in URLs, so the pattern is strict.
var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9]|-[a-z0-9]){0,39}$`)

const (
	maxSlugLen = 40
	maxNameLen = 100
)

// Org is a tenant. Every tenant-scoped row carries its OrgID.
type Org struct {
	ID        string
	Slug      string
	Name      string
	CreatedAt time.Time
}

// Project belongs to exactly one Org and groups pipelines and runs.
type Project struct {
	ID        string
	OrgID     string
	Slug      string
	Name      string
	CreatedAt time.Time
}

// User is a human identity, keyed by the (issuer, subject) pair from the IdP.
type User struct {
	ID          string
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	// InstanceAdmin may perform instance-level actions such as creating orgs.
	InstanceAdmin bool
	CreatedAt     time.Time
}

// Member is a user's membership as shown in an org's member list.
type Member struct {
	UserID      string
	Email       string
	DisplayName string
	Role        Role
}

// Membership links a user to an org with a role.
type Membership struct {
	OrgID  string
	UserID string
	Role   Role
}

// OrgWithRole is an org as seen by one member.
type OrgWithRole struct {
	Org
	Role Role
}

// ValidateSlug reports whether s is a valid org or project slug.
func ValidateSlug(field, s string) error {
	if len(s) > maxSlugLen || !slugPattern.MatchString(s) {
		return NewValidationError(field, "must be 1-40 lowercase letters, digits, or single hyphens, starting and ending with a letter or digit")
	}
	return nil
}

// NormalizeName trims s and validates it as a display name.
func NormalizeName(field, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxNameLen {
		return "", NewValidationError(field, "must be 1-100 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", NewValidationError(field, "must not contain control characters")
		}
	}
	return s, nil
}
