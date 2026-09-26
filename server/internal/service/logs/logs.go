// SPDX-License-Identifier: Apache-2.0

// Package logs stores and serves job output (ADR-0007).
//
// Writes come only from the runner holding the job's lease, already masked,
// as numbered chunks. Chunks are stored in object storage; PostgreSQL keeps
// only metadata (sequence, size, SHA-256, key). Appends are idempotent per
// sequence number and content, gap-free, and capped per job. Reads and live
// streams are authorized against the specific org and project; a streaming
// reader is woken by the bus and re-reads state from the store.
package logs

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/bus"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ids"
	"github.com/yamatrireddy/kilnci/server/internal/platform/objstore"
	"github.com/yamatrireddy/kilnci/server/internal/scheduler"
	"github.com/yamatrireddy/kilnci/server/internal/store"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/service/logs")

// Limits (ADR-0007 §1).
const (
	MaxChunkBytes = 256 << 10
	MaxChunks     = 16384
	DefaultMaxLog = 64 << 20
)

// TruncationMarker is appended when a job reaches its log limit.
const TruncationMarker = "\n[kiln: log truncated: size limit reached]\n"

// Store is the persistence this service needs.
type Store interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	GetOrgForMember(ctx context.Context, slug, userID string) (domain.OrgWithRole, error)
	GetProject(ctx context.Context, orgID, slug string) (domain.Project, error)
	GetLeasedJob(ctx context.Context, ref store.LeaseRef, now time.Time) (domain.Job, error)
	LockJobLogState(ctx context.Context, orgID, jobID string) (store.JobLogState, error)
	GetJobLogChunk(ctx context.Context, orgID, jobID string, seq int) (store.LogChunk, error)
	InsertJobLogChunk(ctx context.Context, orgID, jobID string, c store.LogChunk, truncated bool, now time.Time) error
	MarkJobLogTruncated(ctx context.Context, orgID, jobID string) error
	ListJobLogChunks(ctx context.Context, orgID, jobID string, fromSeq int, limit int32) ([]store.LogChunk, error)
	GetRunJob(ctx context.Context, orgID, projectID, runID, jobID string) (store.RunJob, error)
}

// Authorizer decides whether a principal may act on a resource.
type Authorizer interface {
	Check(ctx context.Context, p *authz.Principal, a authz.Action, res authz.Resource) error
}

// Options configures the service.
type Options struct {
	// MaxLogBytes per job. Default 64 MiB.
	MaxLogBytes int64
	// StreamPoll is how often a stream re-checks without a bus wake-up.
	// Default 5s.
	StreamPoll time.Duration
	// MaxStream bounds one stream's duration. Default 30m.
	MaxStream time.Duration
}

// Service stores and serves logs.
type Service struct {
	store Store
	az    Authorizer
	obj   objstore.Store
	bus   bus.Bus
	opts  Options
	now   func() time.Time
}

// NewService returns a Service. now may be nil.
func NewService(s Store, az Authorizer, obj objstore.Store, b bus.Bus, opts Options, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if opts.MaxLogBytes <= 0 {
		opts.MaxLogBytes = DefaultMaxLog
	}
	if opts.StreamPoll <= 0 {
		opts.StreamPoll = 5 * time.Second
	}
	if opts.MaxStream <= 0 {
		opts.MaxStream = 30 * time.Minute
	}
	return &Service{store: s, az: az, obj: obj, bus: b, opts: opts, now: now}
}

func objectKey(orgID, runID, jobID string, seq int) string {
	return strings.ToLower(fmt.Sprintf("orgs/%s/runs/%s/jobs/%s/%08d", orgID, runID, jobID, seq))
}

// Append stores chunk seq of a leased job's output. It returns truncated
// when the job's log limit is reached (further chunks are acknowledged and
// dropped). Only the runner holding the lease may append (ADR-0007 §1).
func (s *Service) Append(ctx context.Context, r scheduler.Runner, jobID string, leaseID []byte, seq int, data []byte) (bool, error) {
	ctx, span := tracer.Start(ctx, "logs.Append")
	defer span.End()
	if len(data) > MaxChunkBytes {
		return false, domain.NewValidationError("data", "must be at most 256 KiB")
	}
	if seq < 0 || seq >= MaxChunks {
		return true, nil // past the chunk limit: acknowledged and dropped
	}
	now := s.now().UTC()
	job, err := s.store.GetLeasedJob(ctx, store.LeaseRef{OrgID: r.OrgID, JobID: jobID, RunnerID: r.ID, LeaseID: leaseID}, now)
	if errors.Is(err, domain.ErrNotFound) {
		return false, scheduler.ErrLeaseLost
	}
	if err != nil {
		return false, fmt.Errorf("append logs: %w", err)
	}
	sum := sha256.Sum256(data)
	var truncated bool
	err = s.store.InTx(ctx, func(ctx context.Context) error {
		st, err := s.store.LockJobLogState(ctx, job.OrgID, job.ID)
		if err != nil {
			return err //nolint:wrapcheck // store errors are contextual
		}
		if seq < st.Chunks {
			prev, err := s.store.GetJobLogChunk(ctx, job.OrgID, job.ID, seq)
			if err != nil {
				return err //nolint:wrapcheck // store errors are contextual
			}
			if subtle.ConstantTimeCompare(prev.SHA256, sum[:]) != 1 {
				return fmt.Errorf("chunk %d was already stored with different content: %w", seq, domain.ErrConflict)
			}
			truncated = st.Truncated
			return nil // idempotent replay
		}
		if st.Truncated {
			truncated = true // the limit was reached: acknowledge and drop
			return nil
		}
		if seq != st.Chunks {
			return domain.NewValidationError("seq", "chunks must be sent in order without gaps")
		}
		body := data
		if room := s.opts.MaxLogBytes - st.Bytes; int64(len(body)) > room {
			cut := max(room-int64(len(TruncationMarker)), 0)
			body = append(append([]byte{}, body[:min(int64(len(body)), cut)]...), TruncationMarker...)
			truncated = true
		}
		key := objectKey(job.OrgID, job.RunID, job.ID, seq)
		if err := s.obj.Put(ctx, key, body); err != nil {
			return fmt.Errorf("store log chunk: %w", err)
		}
		stored := sum
		if truncated {
			stored = sha256.Sum256(body)
		}
		return s.store.InsertJobLogChunk(ctx, job.OrgID, job.ID, store.LogChunk{
			Seq: seq, Size: len(body), SHA256: stored[:], ObjectKey: key,
		}, truncated, now)
	})
	if err != nil {
		return false, fmt.Errorf("append logs: %w", err)
	}
	s.notify(ctx, job.OrgID, job.ID)
	return truncated, nil
}

// Notify wakes readers of a job's log (e.g. when the job finishes).
func (s *Service) Notify(ctx context.Context, orgID, jobID string) { s.notify(ctx, orgID, jobID) }

func (s *Service) notify(ctx context.Context, orgID, jobID string) {
	// Best effort: streams also poll, so a lost notification only adds latency.
	_ = s.bus.Publish(ctx, bus.JobLogs(orgID, jobID))
}

func principal(ctx context.Context) (*authz.Principal, error) {
	p, ok := authz.FromContext(ctx)
	if !ok {
		return nil, domain.ErrUnauthenticated
	}
	return p, nil
}

// JobRef names a job through the path the caller used.
type JobRef struct {
	OrgSlug, ProjectSlug, RunID, JobID string
}

func (s *Service) resolve(ctx context.Context, ref JobRef) (store.RunJob, error) {
	p, err := principal(ctx)
	if err != nil {
		return store.RunJob{}, err
	}
	if domain.ValidateSlug("orgSlug", ref.OrgSlug) != nil || domain.ValidateSlug("projectSlug", ref.ProjectSlug) != nil ||
		!ids.Valid(ref.RunID) || !ids.Valid(ref.JobID) {
		return store.RunJob{}, domain.ErrNotFound
	}
	org, err := s.store.GetOrgForMember(ctx, ref.OrgSlug, p.UserID)
	if err != nil {
		return store.RunJob{}, fmt.Errorf("resolve org: %w", err)
	}
	if err := s.az.Check(ctx, p, authz.ActionLogsRead, authz.Resource{OrgID: org.ID}); err != nil {
		return store.RunJob{}, fmt.Errorf("authorize: %w", err)
	}
	proj, err := s.store.GetProject(ctx, org.ID, ref.ProjectSlug)
	if err != nil {
		return store.RunJob{}, fmt.Errorf("resolve project: %w", err)
	}
	job, err := s.store.GetRunJob(ctx, org.ID, proj.ID, ref.RunID, ref.JobID)
	if err != nil {
		return store.RunJob{}, fmt.Errorf("resolve job: %w", err)
	}
	return job, nil
}

// Authorize checks that the caller may read the job's log before a
// response is committed (e.g. before a stream starts).
func (s *Service) Authorize(ctx context.Context, ref JobRef) error {
	_, err := s.resolve(ctx, ref)
	return err
}

const listBatch = 100

// Read writes the job's stored log to w.
func (s *Service) Read(ctx context.Context, ref JobRef, w io.Writer) error {
	ctx, span := tracer.Start(ctx, "logs.Read")
	defer span.End()
	job, err := s.resolve(ctx, ref)
	if err != nil {
		return err
	}
	_, err = s.copyChunks(ctx, job, 0, func(_ int, data []byte) error {
		_, err := w.Write(data)
		return err //nolint:wrapcheck // caller's writer
	})
	return err
}

// copyChunks emits every stored chunk from seq on and returns the next seq.
func (s *Service) copyChunks(ctx context.Context, job store.RunJob, from int, emit func(seq int, data []byte) error) (int, error) {
	next := from
	for {
		chunks, err := s.store.ListJobLogChunks(ctx, job.OrgID, job.ID, next, listBatch)
		if err != nil {
			return next, fmt.Errorf("list log chunks: %w", err)
		}
		for _, c := range chunks {
			rc, err := s.obj.Get(ctx, c.ObjectKey)
			if err != nil {
				return next, fmt.Errorf("read log chunk: %w", err)
			}
			data, err := io.ReadAll(io.LimitReader(rc, MaxChunkBytes+int64(len(TruncationMarker))))
			_ = rc.Close()
			if err != nil {
				return next, fmt.Errorf("read log chunk: %w", err)
			}
			if err := emit(c.Seq, data); err != nil {
				return next, err
			}
			next = c.Seq + 1
		}
		if len(chunks) < listBatch {
			return next, nil
		}
	}
}

// Event is one item of a live log stream.
type Event struct {
	// Seq and Data are set for a chunk.
	Seq  int
	Data []byte
	// End is set once the job has finished and every chunk was sent.
	End    bool
	Status domain.JobStatus
}

// Stream emits stored chunks from seq from, then follows new chunks until
// the job finishes, ctx ends, or MaxStream passes. It is woken by the bus
// and polls as a fallback. emit errors (the client went away) end it.
func (s *Service) Stream(ctx context.Context, ref JobRef, from int, emit func(Event) error) error {
	ctx, span := tracer.Start(ctx, "logs.Stream")
	defer span.End()
	job, err := s.resolve(ctx, ref)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.opts.MaxStream)
	defer cancel()
	wake, unsubscribe, err := s.bus.Subscribe(bus.JobLogs(job.OrgID, job.ID))
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	defer unsubscribe()
	poll := time.NewTicker(s.opts.StreamPoll)
	defer poll.Stop()
	next := max(from, 0)
	for {
		next, err = s.copyChunks(ctx, job, next, func(seq int, data []byte) error { return emit(Event{Seq: seq, Data: data}) })
		if err != nil {
			return err
		}
		// Re-authorize and re-read the status after copying: access removed
		// mid-stream ends the stream, and a job that finished before the
		// copy has no more chunks coming.
		cur, err := s.resolve(ctx, ref)
		if err != nil {
			return err
		}
		if cur.Status.IsTerminal() {
			if _, err := s.copyChunks(ctx, job, next, func(seq int, data []byte) error {
				return emit(Event{Seq: seq, Data: data})
			}); err != nil {
				return err
			}
			return emit(Event{End: true, Status: cur.Status})
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-poll.C:
		}
	}
}
