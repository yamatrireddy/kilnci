// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/service/logs"
)

func logRequest(p *authz.Principal, org string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.SetPathValue("orgSlug", org)
	if p != nil {
		r = r.WithContext(authz.WithPrincipal(r.Context(), p))
	}
	return r
}

func allow(context.Context) error { return nil }

// TestLogLimiter_CapsPerUserAcrossCredentials: a user's sessions and API
// tokens share one allowance (security review: the cap was per credential).
func TestLogLimiter_CapsPerUserAcrossCredentials(t *testing.T) {
	ll := newLogLimiter()
	var releases []func()
	for i := range maxStreamsPerUser {
		cred := "session"
		if i%2 == 1 {
			cred = "token"
		}
		rel, err := ll.acquire(logRequest(&authz.Principal{UserID: "u1", CredentialID: cred}, "o"), &ll.streams, allow)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		releases = append(releases, rel)
	}
	_, err := ll.acquire(logRequest(&authz.Principal{UserID: "u1", CredentialID: "another-token"}, "o"), &ll.streams, allow)
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("stream over the per-user cap = %v", err)
	}
	// Another user and downloads have their own allowance.
	if rel, err := ll.acquire(logRequest(&authz.Principal{UserID: "u2"}, "o"), &ll.streams, allow); err != nil {
		t.Fatalf("other user: %v", err)
	} else {
		rel()
	}
	if rel, err := ll.acquire(logRequest(&authz.Principal{UserID: "u1"}, "o"), &ll.downloads, allow); err != nil {
		t.Fatalf("download: %v", err)
	} else {
		rel()
	}
	releases[0]()
	if _, err := ll.acquire(logRequest(&authz.Principal{UserID: "u1"}, "o"), &ll.streams, allow); err != nil {
		t.Fatalf("after a release: %v", err)
	}
}

func TestLogLimiter_CapsPerOrgAndInTotal(t *testing.T) {
	ll := newLogLimiter()
	ll.downloads = logLimit{perUser: 2, perOrg: 3, total: 4}
	take := func(user, org string) error {
		_, err := ll.acquire(logRequest(&authz.Principal{UserID: user}, org), &ll.downloads, allow)
		return err
	}
	for _, u := range []string{"a", "b", "c"} {
		if err := take(u, "o1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := take("d", "o1"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("over the per-org cap = %v", err)
	}
	if err := take("d", "o2"); err != nil {
		t.Fatalf("other org: %v", err)
	}
	if err := take("e", "o3"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("over the total cap = %v", err)
	}
}

// TestLogLimiter_UnauthorizedRequestsTakeNoOrgSlot: requests for an org the
// caller cannot read fail authorization and never use that org's slots.
func TestLogLimiter_UnauthorizedRequestsTakeNoOrgSlot(t *testing.T) {
	ll := newLogLimiter()
	ll.streams = logLimit{perUser: 100, perOrg: 1, total: 100}
	for range 5 {
		_, err := ll.acquire(logRequest(&authz.Principal{UserID: "outsider"}, "victim"), &ll.streams,
			func(context.Context) error { return domain.ErrNotFound })
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("unauthorized = %v", err)
		}
	}
	if _, err := ll.acquire(logRequest(&authz.Principal{UserID: "member"}, "victim"), &ll.streams, allow); err != nil {
		t.Fatalf("member after outsider attempts: %v", err)
	}
	if _, err := ll.acquire(logRequest(nil, "victim"), &ll.streams, allow); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("anonymous = %v", err)
	}
}

func TestParseLastEventID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want logs.Position
		ok   bool
	}{
		{"1.0", logs.Position{Attempt: 1, Seq: 1}, true},
		{"3.41", logs.Position{Attempt: 3, Seq: 42}, true},
		{"5", logs.Position{Attempt: 0, Seq: 6}, true},
		{"1.16383", logs.Position{Attempt: 1, Seq: 16384}, true},
		{"1.16384", logs.Position{}, false},
		{"-1", logs.Position{}, false},
		{"1.-1", logs.Position{}, false},
		{"x", logs.Position{}, false},
		{"1.2.3", logs.Position{}, false},
		{"99999999.0", logs.Position{}, false},
	} {
		got, err := parseLastEventID(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseLastEventID(%q) = %+v, %v", tc.in, got, err)
		}
	}
}
