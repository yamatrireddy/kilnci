// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/store/db"
)

// JobLogState is a job's log bookkeeping.
type JobLogState struct {
	Bytes     int64
	Truncated bool
	Chunks    int
}

// LockJobLogState returns a job's log state and locks the job row until
// the transaction ends, serializing appends.
func (s *Store) LockJobLogState(ctx context.Context, orgID, jobID string) (JobLogState, error) {
	r, err := s.q(ctx).LockJobLogState(ctx, db.LockJobLogStateParams{OrgID: orgID, ID: jobID})
	return JobLogState{Bytes: r.LogBytes, Truncated: r.LogTruncated, Chunks: int(r.Chunks)}, mapErr("lock job log state", err)
}

// LogChunk is the metadata of one stored chunk (content is in object storage).
type LogChunk struct {
	Seq       int
	Size      int
	SHA256    []byte
	ObjectKey string
}

// GetJobLogChunk returns one chunk's metadata.
func (s *Store) GetJobLogChunk(ctx context.Context, orgID, jobID string, seq int) (LogChunk, error) {
	sq, err := int32Of("seq", int64(seq))
	if err != nil {
		return LogChunk{}, err
	}
	r, err := s.q(ctx).GetJobLogChunk(ctx, db.GetJobLogChunkParams{OrgID: orgID, JobID: jobID, Seq: sq})
	return LogChunk{Seq: int(r.Seq), Size: int(r.Size), SHA256: r.Sha256, ObjectKey: r.ObjectKey}, mapErr("get job log chunk", err)
}

// InsertJobLogChunk records a stored chunk and adds its size to the job.
func (s *Store) InsertJobLogChunk(ctx context.Context, orgID, jobID string, c LogChunk, truncated bool, now time.Time) error {
	sq, err := int32Of("seq", int64(c.Seq))
	if err != nil {
		return err
	}
	size, err := int32Of("size", int64(c.Size))
	if err != nil {
		return err
	}
	if err := s.q(ctx).InsertJobLogChunk(ctx, db.InsertJobLogChunkParams{
		OrgID: orgID, JobID: jobID, Seq: sq, Size: size, Sha256: c.SHA256, ObjectKey: c.ObjectKey, CreatedAt: now,
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

// ListJobLogChunks lists chunks with seq >= fromSeq, in order.
func (s *Store) ListJobLogChunks(ctx context.Context, orgID, jobID string, fromSeq int, limit int32) ([]LogChunk, error) {
	from, err := int32Of("seq", int64(fromSeq))
	if err != nil {
		return nil, err
	}
	rows, err := s.q(ctx).ListJobLogChunks(ctx, db.ListJobLogChunksParams{OrgID: orgID, JobID: jobID, FromSeq: from, MaxRows: limit})
	if err != nil {
		return nil, mapErr("list job log chunks", err)
	}
	out := make([]LogChunk, len(rows))
	for i, r := range rows {
		out[i] = LogChunk{Seq: int(r.Seq), Size: int(r.Size), ObjectKey: r.ObjectKey}
	}
	return out, nil
}

// RunJob is a job as seen through its run and project.
type RunJob struct {
	ID, OrgID, RunID, Name string
	Status                 domain.JobStatus
	LogBytes               int64
	LogTruncated           bool
}

// GetRunJob finds a job of a run in a project of an org.
func (s *Store) GetRunJob(ctx context.Context, orgID, projectID, runID, jobID string) (RunJob, error) {
	r, err := s.q(ctx).GetRunJob(ctx, db.GetRunJobParams{OrgID: orgID, ProjectID: projectID, RunID: runID, JobID: jobID})
	return RunJob{
		ID: r.ID, OrgID: r.OrgID, RunID: r.RunID, Name: r.Name, Status: domain.JobStatus(r.Status),
		LogBytes: r.LogBytes, LogTruncated: r.LogTruncated,
	}, mapErr("get run job", err)
}
