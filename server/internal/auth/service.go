// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/auth")

// Store is the persistence the auth service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetUser(ctx context.Context, id string) (domain.User, error)
	GetUserByOIDC(ctx context.Context, issuer, subject string) (domain.User, error)
	CreateUser(ctx context.Context, u domain.User) (domain.User, error)
	UpdateUserProfile(ctx context.Context, id, email, displayName string, grantAdmin bool) (domain.User, error)
	ClaimPendingUser(ctx context.Context, email, issuer, subject, displayName string, grantAdmin bool) (domain.User, error)

	CreateWebSession(ctx context.Context, ws domain.WebSession) error
	GetWebSessionByHash(ctx context.Context, hash []byte) (domain.WebSession, error)
	TouchWebSession(ctx context.Context, id string, now time.Time) error
	RevokeWebSession(ctx context.Context, id string, now time.Time) error

	CreateLoginState(ctx context.Context, ls domain.LoginState) error
	TakeLoginState(ctx context.Context, hash []byte) (domain.LoginState, error)
	DeleteExpiredCredentials(ctx context.Context, now time.Time) (int64, error)

	CreateDesktopAuthCode(ctx context.Context, c domain.DesktopAuthCode) error
	UseDesktopAuthCode(ctx context.Context, hash []byte, now time.Time) (domain.DesktopAuthCode, error)
	CreateDesktopGrant(ctx context.Context, g domain.DesktopGrant) error
	GetDesktopGrant(ctx context.Context, id string) (domain.DesktopGrant, error)
	RevokeDesktopGrant(ctx context.Context, id string, now time.Time) error
	CreateRefreshToken(ctx context.Context, t domain.RefreshToken) error
	GetRefreshTokenForUpdate(ctx context.Context, hash []byte) (domain.RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, hash []byte, now time.Time) error
	CreateAccessToken(ctx context.Context, t domain.AccessToken, now time.Time) error
	GetAccessToken(ctx context.Context, hash []byte) (domain.AccessToken, error)

	CreateAPIToken(ctx context.Context, t domain.APIToken, hash []byte) (domain.APIToken, error)
	GetAPITokenByHash(ctx context.Context, hash []byte) (domain.APIToken, error)
	ListAPITokens(ctx context.Context, userID string) ([]domain.APIToken, error)
	CountActiveAPITokens(ctx context.Context, userID string, now time.Time) (int64, error)
	RevokeAPIToken(ctx context.Context, id, userID string, now time.Time) error
	TouchAPIToken(ctx context.Context, id string, now time.Time) error
}

// Auditor records security events.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Options configures the auth service.
type Options struct {
	// PublicOrigin is scheme://host[:port]; unsafe cookie requests must come from it.
	PublicOrigin           string
	SessionIdleTimeout     time.Duration
	SessionAbsoluteTimeout time.Duration
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	AutoProvision          bool
	AllowedEmailDomains    []string
	BootstrapAdminEmails   []string
	RequiredAMR            []string
}

// Timing constants for the login flow (ADR-0003).
const (
	loginStateTTL    = 10 * time.Minute
	desktopCodeTTL   = 60 * time.Second
	grantMaxLifetime = 90 * 24 * time.Hour
	touchInterval    = time.Minute
	maxAPITokens     = 50
)

// Service implements authentication: login flows, credentials, and the
// request Authenticator.
type Service struct {
	store Store
	idp   IdentityProvider
	audit Auditor
	az    Authorizer
	ids   *ids.Generator
	log   *slog.Logger
	now   func() time.Time
	opts  Options
}

// NewService returns an auth Service. now may be nil (time.Now).
func NewService(s Store, idp IdentityProvider, a Auditor, az Authorizer, gen *ids.Generator, log *slog.Logger, now func() time.Time, opts Options) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, idp: idp, audit: a, az: az, ids: gen, log: log, now: now, opts: opts}
}

// StartLoginRequest is the validated input to StartLogin.
type StartLoginRequest struct {
	Client        domain.LoginClient
	ReturnTo      string
	RedirectURI   string
	CodeChallenge string
	State         string
}

// StartLoginResult tells the handler where to send the browser and which
// value to bind to it in the login cookie.
type StartLoginResult struct {
	RedirectURL string
	BrowserBind string
}

var (
	desktopRedirect = regexp.MustCompile(`^http://127\.0\.0\.1:([0-9]{4,5})/callback$`)
	codeChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	desktopStateRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	codeVerifierRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// safeReturnTo accepts only same-origin paths; anything else becomes "/".
// This prevents open redirects through the login flow.
func safeReturnTo(p string) string {
	if p == "" || len(p) > 512 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") ||
		strings.ContainsAny(p, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	return p
}

func validDesktopRedirect(uri string) bool {
	m := desktopRedirect.FindStringSubmatch(uri)
	if m == nil {
		return false
	}
	port, err := strconv.Atoi(m[1])
	return err == nil && port >= 1024 && port <= 65535
}

// StartLogin begins an OIDC login and returns the IdP URL.
func (s *Service) StartLogin(ctx context.Context, req StartLoginRequest) (StartLoginResult, error) {
	ctx, span := tracer.Start(ctx, "auth.StartLogin")
	defer span.End()

	ls := domain.LoginState{Client: req.Client, CreatedAt: s.now().UTC()}
	ls.ExpiresAt = ls.CreatedAt.Add(loginStateTTL)
	switch req.Client {
	case domain.LoginClientWeb:
		ls.ReturnTo = safeReturnTo(req.ReturnTo)
	case domain.LoginClientDesktop:
		ve := &domain.ValidationError{}
		if !validDesktopRedirect(req.RedirectURI) {
			ve.Add("redirectUri", "must be http://127.0.0.1:<port>/callback")
		}
		if !codeChallengeRe.MatchString(req.CodeChallenge) {
			ve.Add("codeChallenge", "must be an S256 PKCE challenge")
		}
		if !desktopStateRe.MatchString(req.State) {
			ve.Add("state", "must be 16-128 URL-safe characters")
		}
		if err := ve.OrNil(); err != nil {
			return StartLoginResult{}, err
		}
		ls.DesktopRedirectURI, ls.DesktopCodeChallenge, ls.DesktopState = req.RedirectURI, req.CodeChallenge, req.State
	default:
		return StartLoginResult{}, domain.NewValidationError("client", "must be web or desktop")
	}

	state := randomString()
	ls.StateHash = hashToken(state)
	ls.Nonce = randomString()
	ls.IDPCodeVerifier = randomString()
	if err := s.store.CreateLoginState(ctx, ls); err != nil {
		return StartLoginResult{}, fmt.Errorf("start login: %w", err)
	}
	// Desktop sign-in mints long-lived tokens for a local listener, so it
	// always requires an interactive login at the IdP: a website cannot
	// silently obtain a code for an already signed-in user.
	u, err := s.idp.AuthCodeURL(ctx, state, ls.Nonce, ls.IDPCodeVerifier, req.Client == domain.LoginClientDesktop)
	if err != nil {
		return StartLoginResult{}, fmt.Errorf("start login: %w", err)
	}
	return StartLoginResult{RedirectURL: u, BrowserBind: state}, nil
}

// CompleteLoginRequest carries the IdP callback parameters and the value of
// the login cookie.
type CompleteLoginRequest struct {
	State       string
	Code        string
	Error       string
	BrowserBind string
}

// CompleteLoginResult tells the handler where to redirect and, for web
// logins, the new session secret to set as a cookie.
type CompleteLoginResult struct {
	Redirect         string
	SessionToken     string
	SessionExpiresAt time.Time
}

// ErrNotInvited means the IdP authenticated a person who has no Kiln account
// and is not eligible for one. It wraps domain.ErrForbidden.
var ErrNotInvited = fmt.Errorf("account not provisioned: %w", domain.ErrForbidden)

// CompleteLogin finishes an OIDC login. It returns domain.ErrUnauthenticated
// for any protocol failure and ErrNotInvited when the person may not sign in.
func (s *Service) CompleteLogin(ctx context.Context, req CompleteLoginRequest) (CompleteLoginResult, error) {
	ctx, span := tracer.Start(ctx, "auth.CompleteLogin")
	defer span.End()
	now := s.now().UTC()

	// The login cookie binds the flow to the browser that started it (login CSRF).
	if req.State == "" || req.BrowserBind == "" || !equalConstantTime(req.State, req.BrowserBind) {
		return CompleteLoginResult{}, fmt.Errorf("login state does not match this browser: %w", domain.ErrUnauthenticated)
	}
	ls, err := s.store.TakeLoginState(ctx, hashToken(req.State))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return CompleteLoginResult{}, fmt.Errorf("unknown or used login state: %w", domain.ErrUnauthenticated)
		}
		return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
	}
	if now.After(ls.ExpiresAt) {
		return CompleteLoginResult{}, fmt.Errorf("login state expired: %w", domain.ErrUnauthenticated)
	}
	if req.Error != "" || req.Code == "" {
		return CompleteLoginResult{}, fmt.Errorf("identity provider returned no code: %w", domain.ErrUnauthenticated)
	}
	claims, err := s.idp.Exchange(ctx, req.Code, ls.IDPCodeVerifier, ls.Nonce)
	if err != nil {
		return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
	}
	if err := checkClaims(claims, s.opts.RequiredAMR); err != nil {
		s.recordLogin(ctx, "", domain.AuditDenied, err.Error())
		return CompleteLoginResult{}, fmt.Errorf("%w: %w", err, domain.ErrUnauthenticated)
	}

	user, err := s.provision(ctx, claims)
	if err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			s.recordLogin(ctx, "", domain.AuditDenied, "not provisioned")
		}
		return CompleteLoginResult{}, err
	}

	switch ls.Client {
	case domain.LoginClientDesktop:
		code, hash := newSecret(PrefixDesktopCode)
		if err := s.store.CreateDesktopAuthCode(ctx, domain.DesktopAuthCode{
			CodeHash: hash, UserID: user.ID, CodeChallenge: ls.DesktopCodeChallenge, RedirectURI: ls.DesktopRedirectURI,
			CreatedAt: now, ExpiresAt: now.Add(desktopCodeTTL),
		}); err != nil {
			return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
		}
		s.recordLogin(ctx, user.ID, domain.AuditSuccess, "desktop")
		q := url.Values{"code": {code}, "state": {ls.DesktopState}}
		return CompleteLoginResult{Redirect: ls.DesktopRedirectURI + "?" + q.Encode()}, nil
	default:
		token, hash := newSecret(PrefixSession)
		ws := domain.WebSession{
			ID: s.ids.New(), TokenHash: hash, UserID: user.ID, CreatedAt: now, LastSeenAt: now,
			ExpiresAt: now.Add(s.opts.SessionAbsoluteTimeout),
		}
		if err := s.store.CreateWebSession(ctx, ws); err != nil {
			return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
		}
		s.recordLogin(ctx, user.ID, domain.AuditSuccess, "web")
		return CompleteLoginResult{Redirect: safeReturnTo(ls.ReturnTo), SessionToken: token, SessionExpiresAt: ws.ExpiresAt}, nil
	}
}

func (s *Service) recordLogin(ctx context.Context, userID string, result domain.AuditResult, detail string) {
	kind := "user"
	if userID == "" {
		kind = "anonymous"
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorKind: kind, ActorID: userID, Action: "auth:login", TargetType: "user", TargetID: userID,
		Result: result, Details: map[string]string{"detail": detail},
	}); err != nil {
		s.log.ErrorContext(ctx, "record login audit event", "error", err)
	}
}

// provision maps verified claims to a Kiln account (ADR-0003 §5).
func (s *Service) provision(ctx context.Context, c Claims) (domain.User, error) {
	email := strings.ToLower(strings.TrimSpace(c.Email))
	name, err := domain.NormalizeName("name", c.Name)
	if err != nil {
		name, _, _ = strings.Cut(email, "@")
	}
	bootstrap := slices.Contains(s.opts.BootstrapAdminEmails, email)

	u, err := s.store.GetUserByOIDC(ctx, c.Issuer, c.Subject)
	switch {
	case err == nil:
		updated, err := s.store.UpdateUserProfile(ctx, u.ID, email, name, bootstrap)
		if errors.Is(err, domain.ErrConflict) {
			// The new email belongs to another account; keep the old one, and
			// decide instance admin from the email this account actually
			// holds, never from the one it failed to claim.
			keep := slices.Contains(s.opts.BootstrapAdminEmails, strings.ToLower(u.Email))
			updated, err = s.store.UpdateUserProfile(ctx, u.ID, u.Email, name, keep)
		}
		if err != nil {
			return domain.User{}, fmt.Errorf("update user: %w", err)
		}
		return updated, nil
	case !errors.Is(err, domain.ErrNotFound):
		return domain.User{}, fmt.Errorf("find user: %w", err)
	}

	u, err = s.store.ClaimPendingUser(ctx, email, c.Issuer, c.Subject, name, bootstrap)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, fmt.Errorf("claim invite: %w", err)
	}

	if !bootstrap && (!s.opts.AutoProvision || !s.domainAllowed(email)) {
		return domain.User{}, ErrNotInvited
	}
	u, err = s.store.CreateUser(ctx, domain.User{
		ID: s.ids.New(), Issuer: c.Issuer, Subject: c.Subject, Email: email, DisplayName: name,
		InstanceAdmin: bootstrap, CreatedAt: s.now().UTC(),
	})
	if errors.Is(err, domain.ErrConflict) {
		// The email is bound to a different identity; never merge accounts.
		return domain.User{}, ErrNotInvited
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func (s *Service) domainAllowed(email string) bool {
	if len(s.opts.AllowedEmailDomains) == 0 {
		return true
	}
	_, d, ok := strings.Cut(email, "@")
	return ok && slices.Contains(s.opts.AllowedEmailDomains, d)
}

// TokenRequest is a desktop token-endpoint request.
type TokenRequest struct {
	GrantType    string
	Code         string
	CodeVerifier string
	RedirectURI  string
	RefreshToken string
}

// TokenPair is a desktop access + refresh token pair.
type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  time.Duration
	RefreshExpiresIn time.Duration
}

// ExchangeToken redeems a desktop login code or rotates a refresh token.
func (s *Service) ExchangeToken(ctx context.Context, req TokenRequest) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "auth.ExchangeToken")
	defer span.End()
	switch req.GrantType {
	case "authorization_code":
		return s.redeemCode(ctx, req)
	case "refresh_token":
		return s.refresh(ctx, req.RefreshToken)
	default:
		return TokenPair{}, domain.NewValidationError("grantType", "must be authorization_code or refresh_token")
	}
}

func (s *Service) redeemCode(ctx context.Context, req TokenRequest) (TokenPair, error) {
	if !wellFormed(req.Code, PrefixDesktopCode) || !codeVerifierRe.MatchString(req.CodeVerifier) {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	now := s.now().UTC()
	// Consume the code in its own committed statement, before checking the
	// verifier, so a wrong verifier burns it and it cannot be retried.
	c, err := s.store.UseDesktopAuthCode(ctx, hashToken(req.Code), now)
	if errors.Is(err, domain.ErrNotFound) {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return TokenPair{}, fmt.Errorf("redeem code: %w", err)
	}
	if now.After(c.ExpiresAt) || !equalConstantTime(pkceS256(req.CodeVerifier), c.CodeChallenge) ||
		!equalConstantTime(req.RedirectURI, c.RedirectURI) {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	userID := c.UserID
	var pair TokenPair
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		g := domain.DesktopGrant{ID: s.ids.New(), UserID: c.UserID, CreatedAt: now, ExpiresAt: now.Add(grantMaxLifetime)}
		if err := s.store.CreateDesktopGrant(ctx, g); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		pair, err = s.issuePair(ctx, g, now)
		return err
	})
	switch {
	case errors.Is(err, errBadGrant) || errors.Is(err, domain.ErrNotFound):
		return TokenPair{}, domain.ErrUnauthenticated
	case err != nil:
		return TokenPair{}, fmt.Errorf("redeem code: %w", err)
	}
	if err := s.audit.Record(ctx, audit.Entry{ActorKind: "user", ActorID: userID, Action: "auth:desktop_grant", TargetType: "user", TargetID: userID}); err != nil {
		s.log.ErrorContext(ctx, "record desktop grant audit event", "error", err)
	}
	return pair, nil
}

// errBadGrant is an internal marker for a rejected code; it becomes
// ErrUnauthenticated without detail.
var errBadGrant = errors.New("bad grant")

func (s *Service) issuePair(ctx context.Context, g domain.DesktopGrant, now time.Time) (TokenPair, error) {
	access, ah := newSecret(PrefixAccessToken)
	refresh, rh := newSecret(PrefixRefreshToken)
	accessExp := minTime(now.Add(s.opts.AccessTokenTTL), g.ExpiresAt)
	refreshExp := minTime(now.Add(s.opts.RefreshTokenTTL), g.ExpiresAt)
	if err := s.store.CreateRefreshToken(ctx, domain.RefreshToken{TokenHash: rh, GrantID: g.ID, CreatedAt: now, ExpiresAt: refreshExp}); err != nil {
		return TokenPair{}, err //nolint:wrapcheck // store errors are contextual
	}
	if err := s.store.CreateAccessToken(ctx, domain.AccessToken{TokenHash: ah, GrantID: g.ID, ExpiresAt: accessExp}, now); err != nil {
		return TokenPair{}, err //nolint:wrapcheck // store errors are contextual
	}
	return TokenPair{
		AccessToken: access, RefreshToken: refresh,
		AccessExpiresIn: accessExp.Sub(now), RefreshExpiresIn: refreshExp.Sub(now),
	}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// refresh rotates a refresh token. Presenting an already-rotated token is
// treated as theft: the whole grant is revoked (and that revocation commits
// even though the request fails).
func (s *Service) refresh(ctx context.Context, token string) (TokenPair, error) {
	if !wellFormed(token, PrefixRefreshToken) {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	now := s.now().UTC()
	var pair TokenPair
	var reused bool
	var grant domain.DesktopGrant
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		rt, err := s.store.GetRefreshTokenForUpdate(ctx, hashToken(token))
		if err != nil {
			return err //nolint:wrapcheck // mapped below
		}
		grant, err = s.store.GetDesktopGrant(ctx, rt.GrantID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if rt.UsedAt != nil {
			reused = true
			return s.store.RevokeDesktopGrant(ctx, grant.ID, now) //nolint:wrapcheck // store errors are contextual
		}
		if grant.RevokedAt != nil || now.After(grant.ExpiresAt) || now.After(rt.ExpiresAt) {
			return errBadGrant
		}
		if err := s.store.MarkRefreshTokenUsed(ctx, rt.TokenHash, now); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		pair, err = s.issuePair(ctx, grant, now)
		return err
	})
	switch {
	case errors.Is(err, errBadGrant) || errors.Is(err, domain.ErrNotFound):
		return TokenPair{}, domain.ErrUnauthenticated
	case err != nil:
		return TokenPair{}, fmt.Errorf("refresh: %w", err)
	case reused:
		if err := s.audit.Record(ctx, audit.Entry{
			ActorKind: "user", ActorID: grant.UserID, Action: "auth:refresh_token_reuse", TargetType: "desktop_grant",
			TargetID: grant.ID, Result: domain.AuditDenied,
		}); err != nil {
			s.log.ErrorContext(ctx, "record refresh reuse audit event", "error", err)
		}
		s.log.WarnContext(ctx, "refresh token reuse detected; desktop grant revoked", "grant_id", grant.ID)
		return TokenPair{}, domain.ErrUnauthenticated
	}
	return pair, nil
}

// SessionInfo describes the current principal for GET /api/v1/session.
type SessionInfo struct {
	User      domain.User
	Method    authz.Method
	CSRFToken string
}

// Session returns information about the caller.
func (s *Service) Session(ctx context.Context) (SessionInfo, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return SessionInfo{}, domain.ErrUnauthenticated
	}
	if err := s.az.Check(ctx, p, authz.ActionSessionRead, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return SessionInfo{}, fmt.Errorf("authorize: %w", err)
	}
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return SessionInfo{}, fmt.Errorf("get user: %w", err)
	}
	return SessionInfo{User: u, Method: p.Method, CSRFToken: p.CSRFToken}, nil
}

// Logout revokes the caller's session or desktop grant. API tokens are
// revoked through the tokens API instead.
func (s *Service) Logout(ctx context.Context) error {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return domain.ErrUnauthenticated
	}
	if err := s.az.Check(ctx, p, authz.ActionSessionDelete, authz.Resource{OwnerUserID: p.UserID}); err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	now := s.now().UTC()
	var err error
	switch {
	case p.Kind == authz.KindUser && p.Method == authz.MethodSession:
		err = s.store.RevokeWebSession(ctx, p.CredentialID, now)
	case p.Kind == authz.KindUser && p.Method == authz.MethodBearer:
		err = s.store.RevokeDesktopGrant(ctx, p.CredentialID, now)
	default:
		return fmt.Errorf("sign out is not available for this credential: %w", domain.ErrForbidden)
	}
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	if err := s.audit.Record(ctx, audit.Entry{Action: "auth:logout", TargetType: "user", TargetID: p.UserID}); err != nil {
		s.log.ErrorContext(ctx, "record logout audit event", "error", err)
	}
	return nil
}

// CleanupExpired deletes expired login states and access tokens.
func (s *Service) CleanupExpired(ctx context.Context) (int64, error) {
	n, err := s.store.DeleteExpiredCredentials(ctx, s.now().UTC())
	if err != nil {
		return 0, fmt.Errorf("delete expired credentials: %w", err)
	}
	return n, nil
}

// RunJanitor calls CleanupExpired every interval until ctx is cancelled.
func (s *Service) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.CleanupExpired(ctx); err != nil {
				s.log.WarnContext(ctx, "janitor", "error", err)
			} else if n > 0 {
				s.log.DebugContext(ctx, "deleted expired credentials", "count", n)
			}
		}
	}
}
