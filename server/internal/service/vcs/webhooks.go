// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/engine/spec"
	"github.com/yamatrireddy/kilnci/server/internal/service/runs"
	"github.com/yamatrireddy/kilnci/server/internal/store"
	"github.com/yamatrireddy/kilnci/server/internal/vcs/github"
	gh "github.com/yamatrireddy/kilnci/server/internal/webhooks/github"
)

// Delivery processing.
const (
	claimBatch      = 20
	maxAttempts     = 5
	dedupeRetention = 90 * 24 * time.Hour
	stalePush       = 7 * 24 * time.Hour
)

// Ingest verifies and queues one webhook delivery (ADR-0008 §3). The
// signature is checked over the raw body before anything is parsed. A
// replayed delivery (same delivery ID or same body) is accepted without
// effect. Unsupported events are accepted and ignored.
func (s *Service) Ingest(ctx context.Context, event, deliveryID, signature string, body []byte) error {
	ctx, span := tracer.Start(ctx, "vcs.Ingest")
	defer span.End()
	if len(s.opts.WebhookSecret) == 0 {
		return ErrNotConfigured
	}
	if err := gh.Verify(s.opts.WebhookSecret, body, signature); err != nil {
		return fmt.Errorf("webhook: %w", domain.ErrUnauthenticated)
	}
	if !gh.Supported(event) {
		return nil
	}
	if !gh.ValidDeliveryID(deliveryID) {
		return domain.NewValidationError(gh.DeliveryHeader, "is not a delivery ID")
	}
	sum := sha256.Sum256(body)
	now := s.now().UTC()
	if _, err := s.store.InsertWebhookDelivery(ctx, store.WebhookDelivery{
		ID: s.ids.New(), DeliveryID: deliveryID, BodySHA256: sum[:], Event: event, Payload: body, ReceivedAt: now,
	}); err != nil {
		return fmt.Errorf("queue webhook: %w", err)
	}
	return nil
}

// ProcessDeliveries handles due deliveries and returns how many it handled.
// Each delivery is first claimed and rescheduled (attempt counted) in a
// short transaction, then handled outside it, so a crash or a GitHub outage
// leads to a later retry; run creation is idempotent per delivery content.
func (s *Service) ProcessDeliveries(ctx context.Context) (int, error) {
	ctx, span := tracer.Start(ctx, "vcs.ProcessDeliveries")
	defer span.End()
	var batch []store.WebhookDelivery
	now := s.now().UTC()
	err := s.store.InTx(ctx, func(ctx context.Context) error {
		claimed, err := s.store.ClaimWebhookDeliveries(ctx, now, claimBatch)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		for _, d := range claimed {
			if d.Attempts >= maxAttempts {
				if err := s.store.FinishWebhookDelivery(ctx, d.ID, true, "failed", now); err != nil {
					return err //nolint:wrapcheck // store errors are contextual
				}
				continue
			}
			backoff := time.Duration(5<<d.Attempts) * time.Second
			if err := s.store.RetryWebhookDelivery(ctx, d.ID, "processing", now.Add(backoff)); err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			batch = append(batch, d)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("claim webhooks: %w", err)
	}
	for _, d := range batch {
		outcome, herr := s.handle(ctx, d)
		if herr != nil {
			s.opts.Log.WarnContext(ctx, "webhook delivery failed; will retry", "delivery", d.ID, "error", herr)
			continue
		}
		if err := s.store.FinishWebhookDelivery(ctx, d.ID, false, outcome, s.now().UTC()); err != nil {
			return 0, fmt.Errorf("finish webhook: %w", err)
		}
	}
	return len(batch), nil
}

// handle processes one delivery and returns a short outcome for the record.
// Errors mean "retry"; permanent problems are outcomes, not errors.
func (s *Service) handle(ctx context.Context, d store.WebhookDelivery) (string, error) {
	switch d.Event {
	case "push":
		var p gh.Push
		if !decodes(d.Payload, &p) {
			return "ignored: malformed", nil
		}
		return s.handlePush(ctx, &p)
	case "pull_request":
		var p gh.PullRequest
		if !decodes(d.Payload, &p) {
			return "ignored: malformed", nil
		}
		return s.handlePullRequest(ctx, &p)
	case "installation":
		var p gh.InstallationEvent
		if !decodes(d.Payload, &p) {
			return "ignored: malformed", nil
		}
		if p.Action == "deleted" || p.Action == "suspend" {
			if err := s.store.DisableGitHubInstallation(ctx, p.Installation.ID, s.now().UTC()); err != nil {
				return "", err //nolint:wrapcheck // store errors are contextual
			}
			return "installation disabled", nil
		}
		return "ignored", nil
	case "installation_repositories":
		var p gh.InstallationRepositories
		if !decodes(d.Payload, &p) {
			return "ignored: malformed", nil
		}
		if p.Action != "removed" || len(p.RepositoriesRemoved) == 0 {
			return "ignored", nil
		}
		ids := make([]int64, len(p.RepositoriesRemoved))
		for i, r := range p.RepositoriesRemoved {
			ids[i] = r.ID
		}
		if err := s.store.DisableRepositories(ctx, p.Installation.ID, ids, s.now().UTC()); err != nil {
			return "", err //nolint:wrapcheck // store errors are contextual
		}
		return "repositories disabled", nil
	default:
		return "ignored", nil
	}
}

// decodes reports whether a verified payload has the expected shape;
// malformed payloads are recorded as ignored, not retried.
func decodes(body []byte, v any) bool { return gh.Decode(body, v) == nil }

// linkFor finds the active link for repoID and checks that the event came
// from the installation that link was made through (ADR-0008 §2).
func (s *Service) linkFor(ctx context.Context, repoID, installationID int64) (domain.Repository, bool, error) {
	link, err := s.store.GetActiveRepositoryByRepoID(ctx, repoID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Repository{}, false, nil
	}
	if err != nil {
		return domain.Repository{}, false, err //nolint:wrapcheck // store errors are contextual
	}
	if link.InstallationID != installationID {
		return domain.Repository{}, false, nil
	}
	return link, true, nil
}

var shaPattern = func(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (s *Service) handlePush(ctx context.Context, p *gh.Push) (string, error) {
	if p.Deleted || !shaPattern(p.After) || strings.Trim(p.After, "0") == "" {
		return "ignored: deletion", nil
	}
	branch, ok := strings.CutPrefix(p.Ref, "refs/heads/")
	if !ok || !validBranch(branch) {
		return "ignored: not a branch", nil
	}
	if p.HeadCommit != nil {
		if ts, err := time.Parse(time.RFC3339, p.HeadCommit.Timestamp); err == nil && s.now().Sub(ts) > stalePush {
			return "ignored: stale", nil
		}
	}
	link, ok, err := s.linkFor(ctx, p.Repository.ID, p.Installation.ID)
	if err != nil || !ok {
		return "ignored: not linked", err
	}
	pl, perr, err := s.loadPipeline(ctx, link, p.After)
	if err != nil {
		return "", err
	}
	if errors.Is(perr, runs.ErrNoPipeline) {
		return "ignored: no pipeline", nil
	}
	if pl != nil && !pl.On.MatchesPush(branch) {
		return "ignored: filtered", nil
	}
	title := ""
	if p.HeadCommit != nil {
		title = p.HeadCommit.Message
	}
	refHash := sha256.Sum256([]byte(p.Ref))
	_, err = s.runs.CreateRun(ctx, runs.NewRun{
		OrgID: link.OrgID, ProjectID: link.ProjectID, Event: domain.EventPush, Ref: p.Ref, Branch: branch,
		CommitSHA: p.After, Title: title, ActorLogin: p.Sender.Login,
		// A push to the linked repository itself is trusted.
		Trusted:        true,
		IdempotencyKey: "gh:push:" + hex.EncodeToString(refHash[:8]) + ":" + p.After,
		Pipeline:       pl, PipelineErr: perr,
	})
	if err != nil {
		return "", fmt.Errorf("create run: %w", err)
	}
	return "run created", nil
}

func (s *Service) handlePullRequest(ctx context.Context, p *gh.PullRequest) (string, error) {
	switch p.Action {
	case "opened", "synchronize", "reopened":
	default:
		return "ignored: action", nil
	}
	pr := p.PullRequest
	if p.Number <= 0 || !shaPattern(pr.Head.SHA) || !validBranch(pr.Base.Ref) || pr.Base.Repo.ID != p.Repository.ID {
		return "ignored: malformed", nil
	}
	link, ok, err := s.linkFor(ctx, pr.Base.Repo.ID, p.Installation.ID)
	if err != nil || !ok {
		return "ignored: not linked", err
	}
	pl, perr, err := s.loadPipeline(ctx, link, pr.Head.SHA)
	if err != nil {
		return "", err
	}
	if errors.Is(perr, runs.ErrNoPipeline) {
		return "ignored: no pipeline", nil
	}
	if pl != nil && !pl.On.MatchesPullRequest(pr.Base.Ref) {
		return "ignored: filtered", nil
	}
	fork := p.IsFork()
	_, err = s.runs.CreateRun(ctx, runs.NewRun{
		OrgID: link.OrgID, ProjectID: link.ProjectID, Event: domain.EventPullRequest,
		Ref: "refs/pull/" + strconv.Itoa(p.Number) + "/head", Branch: pr.Head.Ref, CommitSHA: pr.Head.SHA,
		Title: pr.Title, PRNumber: p.Number, ActorLogin: p.Sender.Login,
		// Only a PR whose head repository is provably the linked repository
		// is trusted; forks (and deleted forks) need approval (ADR-0008 §5).
		IsFork: fork, Trusted: !fork,
		IdempotencyKey: "gh:pr:" + strconv.Itoa(p.Number) + ":" + pr.Head.SHA,
		Pipeline:       pl, PipelineErr: perr,
	})
	if err != nil {
		return "", fmt.Errorf("create run: %w", err)
	}
	return "run created", nil
}

// loadPipeline fetches and parses the pipeline at sha. It returns the parsed
// pipeline or a load problem to record on a failed run (runs.ErrNoPipeline
// when the file is absent) as loadErr, and err only when GitHub could not be
// reached (the caller retries).
func (s *Service) loadPipeline(ctx context.Context, link domain.Repository, sha string) (pl *spec.Pipeline, loadErr, err error) {
	if s.gh == nil {
		return nil, nil, ErrNotConfigured
	}
	body, err := s.gh.GetFile(ctx, link.InstallationID, link.RepoID, spec.Path, sha, spec.MaxBytes)
	if errors.Is(err, github.ErrNotFound) {
		return nil, runs.ErrNoPipeline, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("fetch pipeline: %w", err)
	}
	pl, loadErr = spec.Parse(body)
	return pl, loadErr, nil
}

// validBranch accepts branch names git would accept, conservatively.
func validBranch(b string) bool {
	if b == "" || len(b) > 200 || strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".lock") || strings.Contains(b, "..") || strings.Contains(b, "//") || strings.Contains(b, "@{") {
		return false
	}
	for _, r := range b {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	return true
}

// RunWorker processes webhook deliveries and commit statuses until ctx ends.
func (s *Service) RunWorker(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := s.ProcessDeliveries(ctx); err != nil && ctx.Err() == nil {
			s.opts.Log.ErrorContext(ctx, "process webhook deliveries", "error", err)
		}
		if _, err := s.DeliverStatuses(ctx); err != nil && ctx.Err() == nil {
			s.opts.Log.ErrorContext(ctx, "deliver commit statuses", "error", err)
		}
		if now := s.now(); now.Sub(lastPrune) > time.Hour {
			lastPrune = now
			if _, err := s.store.DeleteOldWebhookDeliveries(ctx, now.Add(-dedupeRetention)); err != nil && ctx.Err() == nil {
				s.opts.Log.WarnContext(ctx, "prune webhook deliveries", "error", err)
			}
		}
	}
}
