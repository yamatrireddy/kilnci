// SPDX-License-Identifier: Apache-2.0

// Package github verifies and decodes GitHub App webhooks (ADR-0008 §3,
// threat T-01). Verify must be called on the raw body before anything is
// parsed; Decode* then extract only the fields Kiln uses. Payload fields are
// attacker-controlled (a fork PR author controls titles and branch names)
// and are treated as data only.
package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// Header names.
const (
	SignatureHeader = "X-Hub-Signature-256"
	EventHeader     = "X-GitHub-Event"
	DeliveryHeader  = "X-GitHub-Delivery"
)

// MaxBodyBytes bounds webhook bodies (SS §5).
const MaxBodyBytes = 5 << 20

// ErrBadSignature means the body was not signed with the webhook secret.
var ErrBadSignature = errors.New("webhook signature mismatch")

// Verify checks the X-Hub-Signature-256 HMAC over the raw body in constant
// time. An empty secret never verifies.
func Verify(secret, body []byte, header string) error {
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(secret) == 0 {
		return ErrBadSignature
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil || len(got) != sha256.Size {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// Sign returns the signature header value for body (tests and tooling).
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Supported events.
var supported = map[string]bool{
	"push": true, "pull_request": true, "installation": true, "installation_repositories": true, "ping": true,
}

// Supported reports whether Kiln processes event.
func Supported(event string) bool { return supported[event] }

// ValidDeliveryID reports whether id looks like a GitHub delivery GUID.
func ValidDeliveryID(id string) bool {
	if id == "" || len(id) > 100 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Repo identifies a repository by its immutable ID.
type Repo struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
}

// Installation identifies the App installation that sent the event.
type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
}

// Push is a push event.
type Push struct {
	Ref          string       `json:"ref"`
	After        string       `json:"after"`
	Deleted      bool         `json:"deleted"`
	Repository   Repo         `json:"repository"`
	Installation Installation `json:"installation"`
	HeadCommit   *struct {
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	} `json:"head_commit"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// PullRequest is a pull_request event.
type PullRequest struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Title string `json:"title"`
		Head  struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo *Repo  `json:"repo"` // null when the fork was deleted
		} `json:"head"`
		Base struct {
			Ref  string `json:"ref"`
			Repo Repo   `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository   Repo         `json:"repository"`
	Installation Installation `json:"installation"`
	Sender       struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// IsFork reports whether the PR comes from another repository. A missing
// head repository (a deleted fork) counts as a fork (fail closed).
func (p *PullRequest) IsFork() bool {
	h := p.PullRequest.Head.Repo
	return h == nil || h.ID == 0 || h.ID != p.PullRequest.Base.Repo.ID
}

// InstallationEvent is an installation event.
type InstallationEvent struct {
	Action       string       `json:"action"`
	Installation Installation `json:"installation"`
}

// InstallationRepositories is an installation_repositories event.
type InstallationRepositories struct {
	Action              string       `json:"action"`
	Installation        Installation `json:"installation"`
	RepositoriesRemoved []Repo       `json:"repositories_removed"`
}

// Decode parses a verified payload into v.
func Decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("malformed webhook payload")
	}
	return nil
}
