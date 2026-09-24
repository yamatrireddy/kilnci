// SPDX-License-Identifier: Apache-2.0

package domain

// Role is an org-level role. Roles are ordered: each includes the permissions of
// the roles below it. What each role may do is decided by the policy in
// internal/auth, not here.
type Role string

// Org roles, lowest to highest.
const (
	RoleViewer    Role = "viewer"
	RoleDeveloper Role = "developer"
	RoleAdmin     Role = "admin"
	RoleOwner     Role = "owner"
)

// AllRoles lists every role from lowest to highest privilege.
var AllRoles = []Role{RoleViewer, RoleDeveloper, RoleAdmin, RoleOwner}

// Rank returns the role's privilege rank, or -1 for an unknown role. Unknown
// roles therefore satisfy no minimum, which keeps authorization deny-by-default.
func (r Role) Rank() int {
	for i, x := range AllRoles {
		if x == r {
			return i
		}
	}
	return -1
}

// AtLeast reports whether r grants at least the privileges of min.
func (r Role) AtLeast(minRole Role) bool {
	return r.Rank() >= 0 && minRole.Rank() >= 0 && r.Rank() >= minRole.Rank()
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r.Rank() >= 0 }
