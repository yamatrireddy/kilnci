// SPDX-License-Identifier: Apache-2.0

// Package secrets implements pipeline secret management (ADR-0009): org
// admins create, replace, and delete org and project secrets; developers
// list their metadata. Values are write-only: they are sealed with the
// org's data key (internal/secrets) inside the request and never returned,
// logged, or audited.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/logging"
	"github.com/yamatrireddy/kilnci/server/internal/secrets"
	"github.com/yamatrireddy/kilnci/server/internal/service/audit"
	"github.com/yamatrireddy/kilnci/server/internal/service/paging"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/secrets")

// ErrNotConfigured means no key-encryption key provider is configured, so
// secrets cannot be written (ADR-0009 §2).
var ErrNotConfigured = fmt.Errorf("secrets are not configured on this server (set KILN_SECRETS_PROVIDER): %w", domain.ErrUnavailable)

// WarningNotMasked is returned when a value is too short for the runner to
// mask (maintainer decision, 2026-09-27).
const WarningNotMasked = "The value is shorter than 4 bytes, so it will not be masked in job logs."

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	GetProject(ctx context.Context, orgID, slug string) (domain.Project, error)
	GetActiveDataKey(ctx context.Context, orgID string) (store.DataKey, error)
	InsertFirstDataKey(ctx context.Context, k store.DataKey) (bool, error)
	CountDataKeysNotWrappedBy(ctx context.Context, keyIDs []string) (int64, error)
	CountSecrets(ctx context.Context, orgID, projectID string) (int64, error)
	LockSecretScope(ctx context.Context, orgID, projectID string) error
	LockSecret(ctx context.Context, orgID, projectID, name string) (store.LockedSecret, error)
	InsertSecret(ctx context.Context, w store.SealedSecret) error
	UpdateSecret(ctx context.Context, w store.SealedSecret) error
	ListSecrets(ctx context.Context, orgID, projectID, afterID string, limit int32) ([]domain.Secret, error)
	DeleteSecret(ctx context.Context, orgID, projectID, name string) error
	ProjectSlugsByID(ctx context.Context, orgID string, projectIDs []string) (map[string]string, error)
	ProjectIDsBySlug(ctx context.Context, orgID string, slugs []string) (map[string]string, error)
}

// Keyring creates and unwraps org data keys (internal/secrets.Keyring).
type Keyring interface {
	NewDataKey(ctx context.Context, orgID string) ([]byte, secrets.WrappedKey, error)
	DataKey(ctx context.Context, orgID string, version int32, wk secrets.WrappedKey) ([]byte, error)
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Auditor records privileged actions.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Service implements secret management.
type Service struct {
	store   Store
	az      Authorizer
	audit   Auditor
	keyring Keyring
	ids     *ids.Generator
	now     func() time.Time
}

// NewService returns a Service. keyring may be nil when no provider is
// configured: listing and deleting still work, writing fails with
// ErrNotConfigured. now may be nil.
func NewService(s Store, az Authorizer, a Auditor, keyring Keyring, gen *ids.Generator, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: s, az: az, audit: a, keyring: keyring, ids: gen, now: now}
}

// Input is a create-or-replace request. Value is never stored in plaintext
// and never echoed.
type Input struct {
	Value            string
	Branches         []string
	AllowUnprotected bool
	// AllProjects and ProjectSlugs apply to org secrets only.
	AllProjects  bool
	ProjectSlugs []string
	// IfMatch, when set, is the value version the caller expects to replace.
	IfMatch *int64
}

// View is a secret's metadata as the API shows it.
type View struct {
	domain.Secret
	// ProjectSlugs are the org secret's allowed projects that still exist.
	ProjectSlugs []string
}

// Written is the result of a create or replace.
type Written struct {
	Secret   View
	Created  bool
	Warnings []string
}

// Target names a scope: an org, or a project when ProjectSlug is set.
type Target struct {
	OrgSlug     string
	ProjectSlug string
}

type scope struct {
	orgID     string
	projectID string // empty for the org scope
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

// resolve finds the scope through the caller's membership and authorizes a
// against the org. Unknown orgs and projects are indistinguishable from
// ones the caller cannot see (404).
func (s *Service) resolve(ctx context.Context, t Target, a authz.Action) (*authz.Principal, scope, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, scope{}, err
	}
	if domain.ValidateSlug("orgSlug", t.OrgSlug) != nil {
		return nil, scope{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, t.OrgSlug, p.UserID)
	if err != nil {
		return nil, scope{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, a, authz.Resource{OrgID: org.ID}); err != nil {
		return nil, scope{}, fmt.Errorf("authorize %s: %w", a, err)
	}
	sc := scope{orgID: org.ID}
	if t.ProjectSlug != "" {
		if domain.ValidateSlug("projectSlug", t.ProjectSlug) != nil {
			return nil, scope{}, domain.ErrNotFound
		}
		proj, err := s.store.GetProject(ctx, org.ID, t.ProjectSlug)
		if err != nil {
			return nil, scope{}, fmt.Errorf("resolve project: %w", err)
		}
		sc.projectID = proj.ID
	}
	return p, sc, nil
}

// List returns a page of a scope's secret metadata (developers).
func (s *Service) List(ctx context.Context, t Target, pr paging.Request) (paging.Page[View], error) {
	ctx, span := tracer.Start(ctx, "secrets.List")
	defer span.End()
	_, sc, err := s.resolve(ctx, t, authz.ActionSecretsList)
	if err != nil {
		return paging.Page[View]{}, err
	}
	after, limit, err := pr.Parse()
	if err != nil {
		return paging.Page[View]{}, err //nolint:wrapcheck // validation error
	}
	rows, err := s.store.ListSecrets(ctx, sc.orgID, sc.projectID, after, limit+1)
	if err != nil {
		return paging.Page[View]{}, fmt.Errorf("list secrets: %w", err)
	}
	page := paging.Build(rows, limit, func(x domain.Secret) string { return x.ID })
	views, err := s.views(ctx, sc.orgID, page.Items)
	if err != nil {
		return paging.Page[View]{}, err
	}
	return paging.Page[View]{Items: views, NextCursor: page.NextCursor}, nil
}

func (s *Service) views(ctx context.Context, orgID string, xs []domain.Secret) ([]View, error) {
	var projectIDs []string
	for _, x := range xs {
		projectIDs = append(projectIDs, x.ProjectIDs...)
	}
	slugs := map[string]string{}
	if len(projectIDs) > 0 {
		var err error
		if slugs, err = s.store.ProjectSlugsByID(ctx, orgID, projectIDs); err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
	}
	out := make([]View, len(xs))
	for i, x := range xs {
		out[i] = View{Secret: x, ProjectSlugs: []string{}}
		for _, id := range x.ProjectIDs {
			if slug, ok := slugs[id]; ok {
				out[i].ProjectSlugs = append(out[i].ProjectSlugs, slug)
			}
		}
		slices.Sort(out[i].ProjectSlugs)
	}
	return out, nil
}

// Put creates or replaces a secret (admins).
func (s *Service) Put(ctx context.Context, t Target, name string, in Input) (Written, error) {
	ctx, span := tracer.Start(ctx, "secrets.Put")
	defer span.End()
	p, sc, err := s.resolve(ctx, t, authz.ActionSecretsManage)
	if err != nil {
		return Written{}, err
	}
	if s.keyring == nil {
		return Written{}, ErrNotConfigured
	}
	masked, projectIDs, err := s.validate(ctx, sc, name, &in)
	if err != nil {
		return Written{}, err
	}
	ctx = logging.WithOrgID(ctx, sc.orgID)

	// Unwrapping may call Vault, so it happens before the transaction.
	dek, dekVersion, err := s.activeDataKey(ctx, sc.orgID)
	if err != nil {
		return Written{}, err
	}
	defer clear(dek)

	now := s.now().UTC().Truncate(time.Microsecond)
	var out Written
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		cur, err := s.store.LockSecret(ctx, sc.orgID, sc.projectID, name)
		created := errors.Is(err, domain.ErrNotFound)
		if err != nil && !created {
			return err //nolint:wrapcheck // store errors are contextual
		}
		m := domain.Secret{
			OrgID: sc.orgID, ProjectID: sc.projectID, Name: name, Masked: masked, Branches: in.Branches,
			AllowUnprotected: in.AllowUnprotected, AllProjects: in.AllProjects, ProjectIDs: projectIDs,
			UpdatedBy: p.UserID, UpdatedAt: now,
		}
		if created {
			if in.IfMatch != nil {
				return fmt.Errorf("secret does not exist: %w", domain.ErrPreconditionFailed)
			}
			// Serialises creates in this scope so the per-scope limit holds.
			if err := s.store.LockSecretScope(ctx, sc.orgID, sc.projectID); err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			n, err := s.store.CountSecrets(ctx, sc.orgID, sc.projectID)
			if err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			if n >= domain.MaxSecretsPerScope {
				return domain.NewValidationError("secretName", "this scope already has the maximum of 500 secrets")
			}
			m.ID, m.ValueVersion, m.CreatedBy, m.CreatedAt = s.ids.New(), 1, p.UserID, now
		} else {
			if in.IfMatch == nil {
				return fmt.Errorf("replace without If-Match: %w", domain.ErrPreconditionRequired)
			}
			if *in.IfMatch != cur.Secret.ValueVersion {
				return fmt.Errorf("secret changed: %w", domain.ErrPreconditionFailed)
			}
			m.ID, m.ValueVersion, m.CreatedBy, m.CreatedAt = cur.Secret.ID, cur.Secret.ValueVersion+1, cur.Secret.CreatedBy, cur.Secret.CreatedAt
		}
		ct, err := secrets.Seal(dek, []byte(in.Value), aadFor(m, dekVersion))
		if err != nil {
			return fmt.Errorf("seal secret: %w", err)
		}
		w := store.SealedSecret{Secret: m, DEKVersion: dekVersion, Ciphertext: ct}
		if created {
			err = s.store.InsertSecret(ctx, w)
		} else {
			err = s.store.UpdateSecret(ctx, w)
		}
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		action := "secrets:update"
		if created {
			action = "secrets:create"
		}
		if err := s.audit.Record(ctx, audit.Entry{
			OrgID: sc.orgID, Action: action, TargetType: "secret", TargetID: m.ID, Details: auditDetails(m),
		}); err != nil {
			return err //nolint:wrapcheck // audit errors are contextual
		}
		out = Written{Created: created}
		views, err := s.views(ctx, sc.orgID, []domain.Secret{m})
		if err != nil {
			return err
		}
		out.Secret = views[0]
		return nil
	})
	if err != nil {
		return Written{}, fmt.Errorf("put secret: %w", err)
	}
	if !masked {
		out.Warnings = append(out.Warnings, WarningNotMasked)
	}
	if in.AllowUnprotected {
		out.Warnings = append(out.Warnings, "allowUnprotected is set: every trusted run of this scope, including same-repository pull requests, receives this value, so anyone with push access can read it.")
	}
	return out, nil
}

// validate checks the request and resolves an org secret's project slugs.
func (s *Service) validate(ctx context.Context, sc scope, name string, in *Input) (masked bool, projectIDs []string, err error) {
	if err := domain.ValidateSecretName("secretName", name); err != nil {
		return false, nil, err //nolint:wrapcheck // validation error
	}
	masked, err = domain.ValidateSecretValue("value", in.Value)
	if err != nil {
		return false, nil, err //nolint:wrapcheck // validation error
	}
	if err := domain.ValidateSecretBranches("branches", in.Branches); err != nil {
		return false, nil, err //nolint:wrapcheck // validation error
	}
	in.Branches = append([]string{}, in.Branches...)
	if sc.projectID != "" {
		if in.AllProjects || len(in.ProjectSlugs) > 0 {
			return false, nil, domain.NewValidationError("projectSlugs", "apply to org secrets only")
		}
		return masked, []string{}, nil
	}
	if in.AllProjects && len(in.ProjectSlugs) > 0 {
		return false, nil, domain.NewValidationError("projectSlugs", "must be empty when allProjects is true")
	}
	if len(in.ProjectSlugs) > domain.MaxSecretProjects {
		return false, nil, domain.NewValidationError("projectSlugs", "at most 100 projects")
	}
	for _, slug := range in.ProjectSlugs {
		if domain.ValidateSlug("projectSlugs", slug) != nil {
			return false, nil, domain.NewValidationError("projectSlugs", "contains an invalid slug")
		}
	}
	if len(in.ProjectSlugs) == 0 {
		return masked, []string{}, nil
	}
	bySlug, err := s.store.ProjectIDsBySlug(ctx, sc.orgID, in.ProjectSlugs)
	if err != nil {
		return false, nil, fmt.Errorf("resolve projects: %w", err)
	}
	projectIDs = make([]string, 0, len(in.ProjectSlugs))
	for _, slug := range in.ProjectSlugs {
		id, ok := bySlug[slug]
		if !ok {
			return false, nil, domain.NewValidationError("projectSlugs", "names a project that does not exist in this org")
		}
		if !slices.Contains(projectIDs, id) {
			projectIDs = append(projectIDs, id)
		}
	}
	return masked, projectIDs, nil
}

// aadFor binds a sealed value to its row (T-62).
func aadFor(m domain.Secret, dekVersion int32) secrets.AAD {
	a := secrets.AAD{OrgID: m.OrgID, ScopeKind: secrets.ScopeOrg, ScopeID: m.OrgID, Name: m.Name, SecretID: m.ID, DEKVersion: dekVersion, ValueVersion: m.ValueVersion}
	if m.ProjectID != "" {
		a.ScopeKind, a.ScopeID = secrets.ScopeProject, m.ProjectID
	}
	return a
}

// auditDetails describes a secret write without its value.
func auditDetails(m domain.Secret) map[string]string {
	d := map[string]string{
		"name": m.Name, "scope": string(m.Scope()), "value_version": strconv.FormatInt(m.ValueVersion, 10),
		"masked": strconv.FormatBool(m.Masked), "branches": strings.Join(m.Branches, ","),
		"allow_unprotected": strconv.FormatBool(m.AllowUnprotected),
	}
	if m.ProjectID != "" {
		d["project_id"] = m.ProjectID
	} else {
		d["all_projects"] = strconv.FormatBool(m.AllProjects)
		d["project_ids"] = strings.Join(m.ProjectIDs, ",")
	}
	return d
}

// activeDataKey returns the org's active DEK in plaintext, creating the
// org's first DEK if it has none. The caller clears the returned key.
func (s *Service) activeDataKey(ctx context.Context, orgID string) ([]byte, int32, error) {
	k, err := s.store.GetActiveDataKey(ctx, orgID)
	if errors.Is(err, domain.ErrNotFound) {
		dek, wk, nerr := s.keyring.NewDataKey(ctx, orgID)
		if nerr != nil {
			return nil, 0, fmt.Errorf("create data key: %w", nerr)
		}
		won, ierr := s.store.InsertFirstDataKey(ctx, store.DataKey{OrgID: orgID, KeyID: wk.KeyID, Wrapped: wk.Ciphertext, CreatedAt: s.now().UTC()})
		if ierr != nil {
			clear(dek)
			return nil, 0, fmt.Errorf("store data key: %w", ierr)
		}
		if won {
			return dek, 1, nil
		}
		clear(dek) // a concurrent writer created it first; use theirs
		k, err = s.store.GetActiveDataKey(ctx, orgID)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("get data key: %w", err)
	}
	dek, err := s.keyring.DataKey(ctx, orgID, k.Version, secrets.WrappedKey{KeyID: k.KeyID, Ciphertext: k.Wrapped})
	if err != nil {
		return nil, 0, fmt.Errorf("unwrap data key: %w", err)
	}
	return dek, k.Version, nil
}

// Delete deletes a secret (admins).
func (s *Service) Delete(ctx context.Context, t Target, name string) error {
	ctx, span := tracer.Start(ctx, "secrets.Delete")
	defer span.End()
	_, sc, err := s.resolve(ctx, t, authz.ActionSecretsManage)
	if err != nil {
		return err
	}
	if domain.ValidateSecretName("secretName", name) != nil {
		return domain.ErrNotFound
	}
	ctx = logging.WithOrgID(ctx, sc.orgID)
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		cur, err := s.store.LockSecret(ctx, sc.orgID, sc.projectID, name)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if err := s.store.DeleteSecret(ctx, sc.orgID, sc.projectID, name); err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		d := map[string]string{"name": name, "scope": string(cur.Secret.Scope())}
		if sc.projectID != "" {
			d["project_id"] = sc.projectID
		}
		return s.audit.Record(ctx, audit.Entry{OrgID: sc.orgID, Action: "secrets:delete", TargetType: "secret", TargetID: cur.Secret.ID, Details: d})
	})
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// VerifyDataKeys fails when any stored DEK was wrapped by a key the
// provider does not know, so a master key removed too early stops the
// server at startup instead of failing leases later (ADR-0009 §2).
func (s *Service) VerifyDataKeys(ctx context.Context, knownKeyIDs []string) error {
	n, err := s.store.CountDataKeysNotWrappedBy(ctx, knownKeyIDs)
	if err != nil {
		return fmt.Errorf("verify data keys: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("%d secret data key(s) were wrapped by a key-encryption key this server does not have; "+
			"configure the previous key (KILN_MASTER_KEY_PREVIOUS_FILE, or lower Vault's min_decryption_version) and run `kiln-server secrets rewrap`", n)
	}
	return nil
}
