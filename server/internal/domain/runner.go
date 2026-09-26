// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"regexp"
	"time"
)

// Runner is a registered agent that leases and executes jobs for one org.
type Runner struct {
	ID      string
	OrgID   string
	Name    string
	Labels  []string
	Trusted bool
	Version string
	// Capacity is how many jobs the runner may hold at once.
	Capacity int
	// CertSerial is the current client-certificate serial (hex);
	// PrevCertSerial the one it replaced, accepted briefly after renewal.
	CertSerial string
	// CertDER and CertSPKIHash describe the current certificate, so a
	// renewal retried after a lost response returns it instead of looking
	// like credential reuse.
	CertDER        []byte
	CertSPKIHash   []byte
	PrevCertSerial string
	CertRenewedAt  time.Time
	CertExpiresAt  time.Time
	CreatedBy      string
	CreatedAt      time.Time
	LastSeenAt     *time.Time
	RevokedAt      *time.Time
}

// RunnerRegistrationToken is the metadata of a single-use registration token.
type RunnerRegistrationToken struct {
	ID        string
	OrgID     string
	Labels    []string
	Trusted   bool
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// runnerLabelPattern matches the pipeline spec's runs-on labels.
var runnerLabelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// MaxRunnerLabels bounds how many labels a runner may carry.
const MaxRunnerLabels = 20

// ValidateRunnerLabels checks labels against the pipeline label rules.
func ValidateRunnerLabels(field string, labels []string) error {
	if len(labels) > MaxRunnerLabels {
		return NewValidationError(field, "must have at most 20 labels")
	}
	seen := map[string]bool{}
	for _, l := range labels {
		if !runnerLabelPattern.MatchString(l) || seen[l] {
			return NewValidationError(field, "must be unique labels matching ^[a-z0-9][a-z0-9._-]{0,62}$")
		}
		seen[l] = true
	}
	return nil
}
