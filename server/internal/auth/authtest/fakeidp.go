// SPDX-License-Identifier: Apache-2.0

// Package authtest provides a fake OIDC identity provider for tests.
package authtest

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/yamatrireddy/kilnci/server/internal/auth"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// FakeIDP implements auth.IdentityProvider. Codes have the form
// "<identity-key>.<state>"; Exchange succeeds only if the verifier and nonce
// match what AuthCodeURL was given for that state, so tests fail if the
// service mixes up PKCE or nonce values.
type FakeIDP struct {
	mu         sync.Mutex
	pending    map[string]pending
	identities map[string]auth.Claims
}

type pending struct{ nonce, verifier string }

// NewFakeIDP returns an empty fake.
func NewFakeIDP() *FakeIDP {
	return &FakeIDP{pending: map[string]pending{}, identities: map[string]auth.Claims{}}
}

// Register makes key a valid identity.
func (f *FakeIDP) Register(key string, c auth.Claims) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[key] = c
}

// AuthCodeURL implements auth.IdentityProvider.
func (f *FakeIDP) AuthCodeURL(_ context.Context, state, nonce, verifier string, forceLogin bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending[state] = pending{nonce: nonce, verifier: verifier}
	q := url.Values{"state": {state}}
	if forceLogin {
		q.Set("prompt", "login")
	}
	return "https://idp.test/authorize?" + q.Encode(), nil
}

// Exchange implements auth.IdentityProvider.
func (f *FakeIDP) Exchange(_ context.Context, code, verifier, nonce string) (auth.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, state, _ := strings.Cut(code, ".")
	p, ok := f.pending[state]
	if !ok || p.verifier != verifier || p.nonce != nonce {
		return auth.Claims{}, domain.ErrUnauthenticated
	}
	delete(f.pending, state)
	c, ok := f.identities[key]
	if !ok {
		return auth.Claims{}, domain.ErrUnauthenticated
	}
	return c, nil
}
