// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// Claims are the verified identity attributes Kiln uses from an ID token.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	AMR           []string
}

// IdentityProvider is an OIDC identity provider. The interface exists so the
// login flow can be tested without a live IdP.
type IdentityProvider interface {
	// AuthCodeURL returns the IdP authorization URL for state, nonce, and the
	// S256 PKCE challenge of verifier. forceLogin asks the IdP to
	// re-authenticate the user (prompt=login) even if they have a session.
	AuthCodeURL(ctx context.Context, state, nonce, verifier string, forceLogin bool) (string, error)
	// Exchange redeems code with the PKCE verifier and returns verified
	// claims. Implementations must verify the ID token signature, issuer,
	// audience, and expiry, and that its nonce equals nonce.
	Exchange(ctx context.Context, code, verifier, nonce string) (Claims, error)
}

// OIDCOptions configures NewOIDCProvider.
type OIDCOptions struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // empty for a public, PKCE-only client
	RedirectURL  string
	// HTTPClient must be platform/httpclient (SSRF protection).
	HTTPClient *http.Client
}

// OIDCProvider implements IdentityProvider with go-oidc. Discovery is lazy and
// retried on failure, so the server starts even if the IdP is briefly down.
type OIDCProvider struct {
	opts OIDCOptions

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider returns a provider; no network calls are made yet.
func NewOIDCProvider(opts OIDCOptions) *OIDCProvider {
	return &OIDCProvider{opts: opts}
}

func (o *OIDCProvider) init(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.oauth != nil {
		return o.oauth, o.verifier, nil
	}
	ctx = oidc.ClientContext(ctx, o.opts.HTTPClient)
	provider, err := oidc.NewProvider(ctx, o.opts.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	o.oauth = &oauth2.Config{
		ClientID:     o.opts.ClientID,
		ClientSecret: o.opts.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  o.opts.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	o.verifier = provider.VerifierContext(oidc.ClientContext(context.WithoutCancel(ctx), o.opts.HTTPClient),
		&oidc.Config{ClientID: o.opts.ClientID})
	return o.oauth, o.verifier, nil
}

// AuthCodeURL implements IdentityProvider.
func (o *OIDCProvider) AuthCodeURL(ctx context.Context, state, nonce, verifier string, forceLogin bool) (string, error) {
	conf, _, err := o.init(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if forceLogin {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	return conf.AuthCodeURL(state, opts...), nil
}

// Exchange implements IdentityProvider.
func (o *OIDCProvider) Exchange(ctx context.Context, code, verifier, nonce string) (Claims, error) {
	conf, idv, err := o.init(ctx)
	if err != nil {
		return Claims{}, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, o.opts.HTTPClient)
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("exchange code: %w", domain.ErrUnauthenticated)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, fmt.Errorf("no id_token in token response: %w", domain.ErrUnauthenticated)
	}
	idt, err := idv.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id_token: %w", domain.ErrUnauthenticated)
	}
	if !equalConstantTime(idt.Nonce, nonce) {
		return Claims{}, fmt.Errorf("id_token nonce mismatch: %w", domain.ErrUnauthenticated)
	}
	var c struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		AMR           []string `json:"amr"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("decode claims: %w", domain.ErrUnauthenticated)
	}
	return Claims{
		Issuer: idt.Issuer, Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified,
		Name: c.Name, AMR: c.AMR,
	}, nil
}

// checkClaims applies Kiln's identity requirements to verified claims.
func checkClaims(c Claims, requiredAMR []string) error {
	if c.Issuer == "" || c.Subject == "" {
		return errors.New("id_token lacks issuer or subject")
	}
	if c.Email == "" || !c.EmailVerified {
		return errors.New("the identity provider did not assert a verified email")
	}
	if len(requiredAMR) > 0 && !slices.ContainsFunc(c.AMR, func(m string) bool { return slices.Contains(requiredAMR, m) }) {
		return errors.New("the required authentication method (amr) was not used")
	}
	return nil
}
