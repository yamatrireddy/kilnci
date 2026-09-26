// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// JobLogState is a leased job's log bookkeeping for its current attempt.
type JobLogState struct {
	RunID     string
	Attempt   int
	Bytes     int64
	Truncated bool
	Chunks    int
}

// LockJobLogState returns the log state of the job held under ref and locks
// the job row until the transaction ends, serializing appends. It returns
// domain.ErrNotFound unless ref's lease is still held and unexpired at now.
func (s *Store) LockJobLogState(ctx context.Context, ref LeaseRef, now time.Time) (JobLogState, error) {
	r, err := s.q(ctx).LockJobLogState(ctx, db.LockJobLogStateParams{
		OrgID: ref.OrgID, ID: ref.JobID, RunnerID: &ref.RunnerID, LeaseID: ref.LeaseID, Now: &now,
	})
	if err != nil {
		return JobLogState{}, mapErr("lock job log state", err)
	}
	// Counted in a separate statement, after the lock is held (see the query).
	n, err := s.q(ctx).CountJobLogChunks(ctx, db.CountJobLogChunksParams{OrgID: ref.OrgID, JobID: ref.JobID, Attempt: r.Attempt})
	if err != nil {
		return JobLogState{}, mapErr("count job log chunks", err)
	}
	return JobLogState{
		RunID: r.RunID, Attempt: int(r.Attempt), Bytes: r.LogBytes, Truncated: r.LogTruncated, Chunks: int(n),
	}, nil
}

// LogChunk is the metadata of one stored chunk (content is in object storage).
type LogChunk struct {
	Attempt int
	Seq     int
	Size    int
	// SHA256 is the hash of the stored bytes; RequestSHA256, when set, is
	// the hash of the bytes the runner sent (they differ for the chunk that
	// reached the size limit, which is stored cut short with a marker).
	SHA256        []byte
	RequestSHA256 []byte
	ObjectKey     string
	// RunnerID and LeaseID record who wrote the chunk.
	RunnerID string
	LeaseID  []byte
}

// GetJobLogChunk returns one chunk's metadata.
func (s *Store) GetJobLogChunk(ctx context.Context, orgID, jobID string, attempt, seq int) (LogChunk, error) {
	at, err := int32Of("attempt", int64(attempt))
	if err != nil {
		return LogChunk{}, err
	}
	sq, err := int32Of("seq", int64(seq))
	if err != nil {
		return LogChunk{}, err
	}
	r, err := s.q(ctx).GetJobLogChunk(ctx, db.GetJobLogChunkParams{OrgID: orgID, JobID: jobID, Attempt: at, Seq: sq})
	return LogChunk{
		Attempt: attempt, Seq: int(r.Seq), Size: int(r.Size), SHA256: r.Sha256, RequestSHA256: r.Sha256Request, ObjectKey: r.ObjectKey,
	}, mapErr("get job log chunk", err)
}

// InsertJobLogChunk records a stored chunk and adds its size to the job.
func (s *Store) InsertJobLogChunk(ctx context.Context, orgID, jobID string, c LogChunk, truncated bool, now time.Time) error {
	at, err := int32Of("attempt", int64(c.Attempt))
	if err != nil {
		return err
	}
	sq, err := int32Of("seq", int64(c.Seq))
	if err != nil {
		return err
	}
	size, err := int32Of("size", int64(c.Size))
	if err != nil {
		return err
	}
	if err := s.q(ctx).InsertJobLogChunk(ctx, db.InsertJobLogChunkParams{
		OrgID: orgID, JobID: jobID, Attempt: at, Seq: sq, Size: size, Sha256: c.SHA256, Sha256Request: c.RequestSHA256,
		ObjectKey: c.ObjectKey, RunnerID: &c.RunnerID, LeaseID: c.LeaseID, CreatedAt: now,
	}); err != nil {
		return mapErr("insert job log chunk", err)
	}
	return mapErr("add job log bytes", s.q(ctx).AddJobLogBytes(ctx, db.AddJobLogBytesParams{
		Added: int64(c.Size), Truncated: truncated, OrgID: orgID, ID: jobID,
	}))
}

// MarkJobLogTruncated records that further output was dropped.
func (s *Store) MarkJobLogTruncated(ctx context.Context, orgID, jobID string) error {
	return mapErr("mark job log truncated", s.q(ctx).AddJobLogBytes(ctx, db.AddJobLogBytesParams{
		Added: 0, Truncated: true, OrgID: orgID, ID: jobID,
	}))
}

// ListJobLogChunks lists an attempt's chunks with seq >= fromSeq, in order.
func (s *Store) ListJobLogChunks(ctx context.Context, orgID, jobID string, attempt, fromSeq int, limit int32) ([]LogChunk, error) {
	at, err := int32Of("attempt", int64(attempt))
	if err != nil {
		return nil, err
	}
	from, err := int32Of("seq", int64(fromSeq))
	if err != nil {
		return nil, err
	}
	rows, err := s.q(ctx).ListJobLogChunks(ctx, db.ListJobLogChunksParams{
		OrgID: orgID, JobID: jobID, Attempt: at, FromSeq: from, MaxRows: limit,
	})
	if err != nil {
		return nil, mapErr("list job log chunks", err)
	}
	out := make([]LogChunk, len(rows))
	for i, r := range rows {
		out[i] = LogChunk{Attempt: attempt, Seq: int(r.Seq), Size: int(r.Size), ObjectKey: r.ObjectKey}
	}
	return out, nil
}

// RunJob is a job as seen through its run and project.
type RunJob struct {
	ID, OrgID, RunID, Name string
	Status                 domain.JobStatus
	// Attempt is the job's latest attempt (0 before its first lease); its
	// log is the one served.
	Attempt      int
	LogBytes     int64
	LogTruncated bool
}

// GetRunJob finds a job of a run in a project of an org.
func (s *Store) GetRunJob(ctx context.Context, orgID, projectID, runID, jobID string) (RunJob, error) {
	r, err := s.q(ctx).GetRunJob(ctx, db.GetRunJobParams{OrgID: orgID, ProjectID: projectID, RunID: runID, JobID: jobID})
	return RunJob{
		ID: r.ID, OrgID: r.OrgID, RunID: r.RunID, Name: r.Name, Status: domain.JobStatus(r.Status), Attempt: int(r.Attempt),
		LogBytes: r.LogBytes, LogTruncated: r.LogTruncated,
	}, mapErr("get run job", err)
}
