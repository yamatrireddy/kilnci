// SPDX-License-Identifier: Apache-2.0

package domain

import "time"

// Credential records hold only SHA-256 hashes of high-entropy secrets; the
// secrets themselves are never persisted.

// WebSession is a browser session.
type WebSession struct {
	ID         string
	TokenHash  []byte
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// LoginClient is the kind of client that started a login.
type LoginClient string

// Login clients.
const (
	LoginClientWeb     LoginClient = "web"
	LoginClientDesktop LoginClient = "desktop"
)

// LoginState is an in-flight OIDC login.
type LoginState struct {
	StateHash            []byte
	Client               LoginClient
	Nonce                string
	IDPCodeVerifier      string
	ReturnTo             string
	DesktopRedirectURI   string
	DesktopCodeChallenge string
	DesktopState         string
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

// DesktopAuthCode is a one-time code for the desktop loopback redirect.
type DesktopAuthCode struct {
	CodeHash      []byte
	UserID        string
	CodeChallenge string
	RedirectURI   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

// DesktopGrant is one desktop sign-in, owning a family of tokens.
type DesktopGrant struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// RefreshToken is a rotating desktop refresh token.
type RefreshToken struct {
	TokenHash []byte
	GrantID   string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// AccessToken is a short-lived desktop access token joined with its grant.
type AccessToken struct {
	TokenHash      []byte
	GrantID        string
	UserID         string
	ExpiresAt      time.Time
	GrantRevokedAt *time.Time
	GrantExpiresAt time.Time
}

// APIToken is a personal API token's metadata.
type APIToken struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// AuditResult is the outcome of an audited action.
type AuditResult string

// Audit results.
const (
	AuditSuccess AuditResult = "success"
	AuditDenied  AuditResult = "denied"
)

// AuditEvent is one append-only audit record.
type AuditEvent struct {
	ID         string
	ChainKey   string
	Seq        int64
	OrgID      string // empty for instance-level events
	OccurredAt time.Time
	ActorKind  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Result     AuditResult
	RequestID  string
	SourceIP   string
	UserAgent  string
	Details    map[string]string
	PrevHash   []byte
	Hash       []byte
}
