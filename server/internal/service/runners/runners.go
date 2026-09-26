// SPDX-License-Identifier: Apache-2.0

// Package runners implements runner identity (ADR-0005): org admins create
// single-use registration tokens; a runner exchanges one plus a CSR for an
// identity and a short-lived client certificate; runners renew only from
// their current certificate (anything else is treated as credential reuse
// and revokes the runner); and every runner call is authenticated against
// the database, so revocation is immediate.
package runners

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/platform/pki"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/runners")

// TokenPrefix marks runner registration tokens so secret scanners find them.
const TokenPrefix = "kiln_rrt_"

// Limits and lifetimes.
const (
	MinTokenTTL          = 5 * time.Minute
	MaxTokenTTL          = 24 * time.Hour
	MaxActiveTokens      = 20
	CertTTL              = 24 * time.Hour
	previousSerialGrace  = 5 * time.Minute
	minRenewalInterval   = CertTTL / 4
	maxRunnerNameRunes   = 100
	maxRunnerVersionSize = 64
)

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	CreateRunnerRegistrationToken(ctx context.Context, t domain.RunnerRegistrationToken, hash []byte) error
	ClaimRunnerRegistrationToken(ctx context.Context, hash []byte, now time.Time) (domain.RunnerRegistrationToken, error)
	MarkRunnerRegistrationTokenUsed(ctx context.Context, id, runnerID string, now time.Time) error
	CountActiveRunnerRegistrationTokens(ctx context.Context, orgID string, now time.Time) (int64, error)
	CreateRunner(ctx context.Context, r domain.Runner) error
	GetRunner(ctx context.Context, orgID, id string) (domain.Runner, error)
	LockRunner(ctx context.Context, orgID, id string) (domain.Runner, error)
	ListRunners(ctx context.Context, orgID, afterID string, limit int32) ([]domain.Runner, error)
	RotateRunnerCertificate(ctx context.Context, c store.CertRotation) error
	RevokeRunner(ctx context.Context, orgID, id string, now time.Time) error
	TouchRunner(ctx context.Context, orgID, id string, now time.Time) error
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Auditor records privileged actions.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Signer issues runner certificates (internal/platform/pki).
type Signer interface {
	SignRunnerCSR(csrDER []byte, runnerID, orgID string, now time.Time, ttl time.Duration) (pki.Issued, error)
	CertDER() []byte
}

// Service implements runner identity.
type Service struct {
	store  Store
	az     Authorizer
	audit  Auditor
	signer Signer
	ids    *ids.Generator
	now    func() time.Time
}

// NewService returns a Service. signer may be nil when the runner listener
// is disabled (Register and RenewCertificate then fail). now may be nil.
func NewService(s Store, az Authorizer, a Auditor, signer Signer, gen *ids.Generator, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, az: az, audit: a, signer: signer, ids: gen, now: now}
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

func (s *Service) resolve(ctx context.Context, orgSlug string, a authz.Action) (*authz.Principal, domain.OrgWithRole, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, domain.OrgWithRole{}, err
	}
	if domain.ValidateSlug("orgSlug", orgSlug) != nil {
		return nil, domain.OrgWithRole{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, orgSlug, p.UserID)
	if err != nil {
		return nil, domain.OrgWithRole{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, a, authz.Resource{OrgID: org.ID}); err != nil {
		return nil, domain.OrgWithRole{}, fmt.Errorf("authorize %s: %w", a, err)
	}
	return p, org, nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CreateRegistrationToken creates a single-use registration token for the
// org (org admins). The secret is returned once and only its hash is kept.
func (s *Service) CreateRegistrationToken(ctx context.Context, orgSlug string, labels []string, trusted bool, ttl time.Duration) (string, domain.RunnerRegistrationToken, error) {
	ctx, span := tracer.Start(ctx, "runners.CreateRegistrationToken")
	defer span.End()
	p, org, err := s.resolve(ctx, orgSlug, authz.ActionRunnersManage)
	if err != nil {
		return "", domain.RunnerRegistrationToken{}, err
	}
	if err := domain.ValidateRunnerLabels("labels", labels); err != nil {
		return "", domain.RunnerRegistrationToken{}, err //nolint:wrapcheck // validation error
	}
	if ttl < MinTokenTTL || ttl > MaxTokenTTL {
		return "", domain.RunnerRegistrationToken{}, domain.NewValidationError("expiresInMinutes", "must be between 5 minutes and 24 hours")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", domain.RunnerRegistrationToken{}, fmt.Errorf("generate token: %w", err)
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	now := s.now().UTC()
	t := domain.RunnerRegistrationToken{
		ID: s.ids.New(), OrgID: org.ID, Labels: append([]string{}, labels...), Trusted: trusted,
		CreatedBy: p.UserID, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	ctx = logging.WithOrgID(ctx, org.ID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		n, err := s.store.CountActiveRunnerRegistrationTokens(ctx, org.ID, now)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if n >= MaxActiveTokens {
			return fmt.Errorf("too many active registration tokens: %w", domain.ErrRateLimited)
		}
		if err := s.store.CreateRunnerRegistrationToken(ctx, t, hashToken(token)); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{
			OrgID: org.ID, Action: "runners:token:create", TargetType: "runner_registration_token", TargetID: t.ID,
			Details: map[string]string{"labels": strings.Join(labels, ","), "trusted": fmt.Sprint(trusted), "expires_at": t.ExpiresAt.Format(time.RFC3339)},
		})
	})
	if err != nil {
		return "", domain.RunnerRegistrationToken{}, fmt.Errorf("create registration token: %w", err)
	}
	return token, t, nil
}

// ListRunners lists an org's runners (org admins).
func (s *Service) ListRunners(ctx context.Context, orgSlug string, pr paging.Request) (paging.Page[domain.Runner], error) {
	ctx, span := tracer.Start(ctx, "runners.ListRunners")
	defer span.End()
	_, org, err := s.resolve(ctx, orgSlug, authz.ActionRunnersList)
	if err != nil {
		return paging.Page[domain.Runner]{}, err
	}
	after, limit, err := pr.Parse()
	if err != nil {
		return paging.Page[domain.Runner]{}, err //nolint:wrapcheck // validation error
	}
	rs, err := s.store.ListRunners(ctx, org.ID, after, limit+1)
	if err != nil {
		return paging.Page[domain.Runner]{}, fmt.Errorf("list runners: %w", err)
	}
	return paging.Build(rs, limit, func(r domain.Runner) string { return r.ID }), nil
}

// RevokeRunner revokes a runner (org admins). Its certificate stops working
// on its next call; jobs it holds are re-queued when their leases lapse.
func (s *Service) RevokeRunner(ctx context.Context, orgSlug, runnerID string) error {
	ctx, span := tracer.Start(ctx, "runners.RevokeRunner")
	defer span.End()
	_, org, err := s.resolve(ctx, orgSlug, authz.ActionRunnersManage)
	if err != nil {
		return err
	}
	if !ids.Valid(runnerID) {
		return domain.ErrNotFound
	}
	ctx = logging.WithOrgID(ctx, org.ID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		if err := s.store.RevokeRunner(ctx, org.ID, runnerID, s.now().UTC()); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		return s.audit.Record(ctx, audit.Entry{OrgID: org.ID, Action: "runners:revoke", TargetType: "runner", TargetID: runnerID})
	})
	if err != nil {
		return fmt.Errorf("revoke runner: %w", err)
	}
	return nil
}

// RegisterRequest is a runner's registration.
type RegisterRequest struct {
	Token   string
	CSRDER  []byte
	Name    string
	Version string
}

// Registration is the result of a successful registration.
type Registration struct {
	Runner         domain.Runner
	CertificateDER []byte
	CADER          []byte
}

// ErrDisabled means runner registration is not configured on this server.
var ErrDisabled = errors.New("runner registration is not configured")

// Register consumes a registration token and issues the runner's identity
// and first certificate. Any token problem (unknown, used, expired,
// malformed) is domain.ErrUnauthenticated, without saying which.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (Registration, error) {
	ctx, span := tracer.Start(ctx, "runners.Register")
	defer span.End()
	if s.signer == nil {
		return Registration{}, ErrDisabled
	}
	if !strings.HasPrefix(req.Token, TokenPrefix) || len(req.Token) > 128 {
		return Registration{}, domain.ErrUnauthenticated
	}
	name, err := cleanName(req.Name)
	if err != nil {
		return Registration{}, err
	}
	version := cleanVersion(req.Version)
	now := s.now().UTC()
	var reg Registration
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		tok, err := s.store.ClaimRunnerRegistrationToken(ctx, hashToken(req.Token), now)
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthenticated
		}
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		runnerID := s.ids.New()
		iss, err := s.signer.SignRunnerCSR(req.CSRDER, runnerID, tok.OrgID, now, CertTTL)
		if errors.Is(err, pki.ErrInvalidCSR) {
			return domain.NewValidationError("csr", "must be a PKCS#10 request signed by an ECDSA P-256 or Ed25519 key")
		}
		if err != nil {
			return err //nolint:wrapcheck // contextual
		}
		r := domain.Runner{
			ID: runnerID, OrgID: tok.OrgID, Name: name, Labels: tok.Labels, Trusted: tok.Trusted, Version: version,
			CertSerial: iss.Serial, CertRenewedAt: now, CertExpiresAt: iss.NotAfter, CreatedBy: tok.CreatedBy,
			CreatedAt: now, LastSeenAt: &now,
		}
		if err := s.store.CreateRunner(ctx, r); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if err := s.store.MarkRunnerRegistrationTokenUsed(ctx, tok.ID, runnerID, now); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		reg = Registration{Runner: r, CertificateDER: iss.DER, CADER: s.signer.CertDER()}
		return s.audit.Record(logging.WithOrgID(ctx, tok.OrgID), audit.Entry{
			OrgID: tok.OrgID, ActorKind: "runner_registration_token", ActorID: tok.ID,
			Action: "runners:register", TargetType: "runner", TargetID: runnerID,
			Details: map[string]string{"labels": strings.Join(tok.Labels, ","), "trusted": fmt.Sprint(tok.Trusted), "cert_serial": iss.Serial},
		})
	})
	if err != nil {
		return Registration{}, fmt.Errorf("register runner: %w", err)
	}
	return reg, nil
}

// RenewCertificate issues a new certificate to an authenticated runner.
// Only the current certificate may renew, and not more often than once a
// quarter of a certificate lifetime. A renewal from any other serial means
// two parties hold the runner's credentials: the runner is revoked and the
// reuse is audited (ADR-0005 §4).
func (s *Service) RenewCertificate(ctx context.Context, id pki.Identity, csrDER []byte) (pki.Issued, error) {
	ctx, span := tracer.Start(ctx, "runners.RenewCertificate")
	defer span.End()
	if s.signer == nil {
		return pki.Issued{}, ErrDisabled
	}
	now := s.now().UTC()
	ctx = logging.WithOrgID(ctx, id.OrgID)
	var issued pki.Issued
	var reused bool
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		r, err := s.store.LockRunner(ctx, id.OrgID, id.RunnerID)
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthenticated
		}
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if r.RevokedAt != nil {
			return domain.ErrUnauthenticated
		}
		if id.Serial != r.CertSerial {
			reused = true
			if err := s.store.RevokeRunner(ctx, r.OrgID, r.ID, now); err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			return s.audit.Record(ctx, audit.Entry{
				OrgID: r.OrgID, ActorKind: string(authz.KindRunner), ActorID: r.ID, Action: "runners:revoke",
				TargetType: "runner", TargetID: r.ID, Result: domain.AuditDenied,
				Details: map[string]string{"reason": "certificate_reuse", "presented_serial": id.Serial},
			})
		}
		if now.Before(r.CertRenewedAt.Add(minRenewalInterval)) {
			return fmt.Errorf("renewed too recently: %w", domain.ErrRateLimited)
		}
		iss, err := s.signer.SignRunnerCSR(csrDER, r.ID, r.OrgID, now, CertTTL)
		if errors.Is(err, pki.ErrInvalidCSR) {
			return domain.NewValidationError("csr", "must be a PKCS#10 request signed by an ECDSA P-256 or Ed25519 key")
		}
		if err != nil {
			return err //nolint:wrapcheck // contextual
		}
		if err := s.store.RotateRunnerCertificate(ctx, store.CertRotation{
			OrgID: r.OrgID, RunnerID: r.ID, CurrentSerial: r.CertSerial, NewSerial: iss.Serial, Now: now, ExpiresAt: iss.NotAfter,
		}); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		issued = iss
		return nil
	})
	if err != nil {
		return pki.Issued{}, fmt.Errorf("renew runner certificate: %w", err)
	}
	if reused {
		return pki.Issued{}, fmt.Errorf("renew runner certificate: certificate reuse: %w", domain.ErrUnauthenticated)
	}
	return issued, nil
}

// Authenticate maps a verified client certificate to the runner it
// identifies, as recorded in the database. The runner must not be revoked,
// and the certificate must be its current one (or the one it just
// replaced, for a short grace period).
func (s *Service) Authenticate(ctx context.Context, id pki.Identity) (scheduler.Runner, error) {
	r, err := s.store.GetRunner(ctx, id.OrgID, id.RunnerID)
	if errors.Is(err, domain.ErrNotFound) {
		return scheduler.Runner{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return scheduler.Runner{}, fmt.Errorf("authenticate runner: %w", err)
	}
	now := s.now().UTC()
	current := id.Serial == r.CertSerial
	previous := r.PrevCertSerial != "" && id.Serial == r.PrevCertSerial && now.Before(r.CertRenewedAt.Add(previousSerialGrace))
	if r.RevokedAt != nil || (!current && !previous) {
		return scheduler.Runner{}, domain.ErrUnauthenticated
	}
	if err := s.store.TouchRunner(ctx, r.OrgID, r.ID, now); err != nil {
		return scheduler.Runner{}, fmt.Errorf("authenticate runner: %w", err)
	}
	return scheduler.Runner{ID: r.ID, OrgID: r.OrgID, Labels: r.Labels, Trusted: r.Trusted}, nil
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxRunnerNameRunes || !utf8.ValidString(name) ||
		strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return "", domain.NewValidationError("name", "must be 1-100 characters without control characters")
	}
	return name, nil
}

func cleanVersion(v string) string {
	v = strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII || unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	if len(v) > maxRunnerVersionSize {
		v = v[:maxRunnerVersionSize]
	}
	return v
}
