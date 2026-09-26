// SPDX-License-Identifier: Apache-2.0

package domain

import "time"

// GitHubInstallation is a GitHub App installation bound to one Kiln org by an
// instance admin (ADR-0008 §2).
type GitHubInstallation struct {
	InstallationID int64
	OrgID          string
	AccountLogin   string
	BoundBy        string
	CreatedAt      time.Time
	DisabledAt     *time.Time
}

// Repository links a project to a GitHub repository by its immutable ID.
type Repository struct {
	ID             string
	OrgID          string
	ProjectID      string
	InstallationID int64
	RepoID         int64
	FullName       string
	CloneURL       string
	DefaultBranch  string
	Private        bool
	LinkedBy       string
	CreatedAt      time.Time
	DisabledAt     *time.Time
}
