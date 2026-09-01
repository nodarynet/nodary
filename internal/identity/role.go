// Package identity implements users, roles, TOTP enrollment and tokens:
// docs/specs/07-identity-audit.md §1.
//
// Nothing here opens a database. Every mutating function takes an
// audit.Mutation, so the change and the record describing it commit in one
// transaction, and a caller cannot reach one without going through the audit
// seam (docs/specs/07-identity-audit.md §3).
package identity

import (
	"errors"
	"fmt"
	"slices"
)

// Role is one of the four roles in docs/specs/07-identity-audit.md §1.
type Role string

const (
	// RoleViewer reads state and its own usage.
	RoleViewer Role = "viewer"
	// RoleUser is a viewer that may also use the inference API.
	RoleUser Role = "user"
	// RoleOperator is a user that may also run models and drain nodes.
	RoleOperator Role = "operator"
	// RoleAdmin is everything.
	RoleAdmin Role = "admin"
)

// Roles is every role, weakest first. The order is the rank: §1 defines each
// role as "the above, plus", so the roles are cumulative by construction and a
// permission check is one comparison.
//
// Enumerating a set of permissions per role instead would restate the three
// weaker rows inside the fourth, and that duplication is exactly where a later
// edit grants something it did not mean to.
var Roles = []Role{RoleViewer, RoleUser, RoleOperator, RoleAdmin}

// ErrUnknownRole is returned by ParseRole. It maps to exit code 2.
var ErrUnknownRole = errors.New("unknown role")

// ParseRole reads a role name, rejecting anything outside the four.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("%w %q (want %s)", ErrUnknownRole, s, JoinRoles())
	}
	return r, nil
}

// Valid reports whether r is one of the four roles.
func (r Role) Valid() bool { return slices.Contains(Roles, r) }

// rank orders the roles. Zero means "not a role", so an unset or corrupted
// value holds no permission rather than the weakest one.
func (r Role) rank() int { return slices.Index(Roles, r) + 1 }

// JoinRoles renders the roles for an error message.
func JoinRoles() string {
	names := make([]string, len(Roles))
	for i, r := range Roles {
		names[i] = string(r)
	}
	return joinWords(names)
}

// Permission is one thing a role may do.
//
// Every permission below names a phrase from docs/specs/07-identity-audit.md
// §1's table and nothing else. Two of them — ModelRestart and NodeApprove —
// describe operations no milestone has built yet, because the vocabulary is the
// deliverable here and the operations arrive later and find it.
type Permission string

const (
	// PermStateRead — "Read state".
	PermStateRead Permission = "state.read"
	// PermUsageReadSelf — "read own usage".
	PermUsageReadSelf Permission = "usage.read.self"

	// PermInferenceUse — "use the inference API".
	PermInferenceUse Permission = "inference.use"

	// PermModelEnable, PermModelDisable, PermModelRestart — "enable, disable
	// and restart models".
	PermModelEnable  Permission = "model.enable"
	PermModelDisable Permission = "model.disable"
	PermModelRestart Permission = "model.restart"
	// PermModelStage — "stage weights".
	PermModelStage Permission = "model.stage"
	// PermNodeDrain — "drain nodes".
	PermNodeDrain Permission = "node.drain"

	// PermConfigWrite — "configuration".
	PermConfigWrite Permission = "config.write"
	// PermCatalogWrite — "catalog ... registration".
	PermCatalogWrite Permission = "catalog.write"
	// PermBackendRegister — "backend registration".
	PermBackendRegister Permission = "backend.register"
	// PermNodeApprove — "node approval".
	PermNodeApprove Permission = "node.approve"
	// PermUserManage — "user ... management".
	PermUserManage Permission = "user.manage"
	// PermTokenManage — "token management".
	PermTokenManage Permission = "token.manage"
	// PermPolicyApply — "policy".
	PermPolicyApply Permission = "policy.apply"
)

// minimumRole is the weakest role holding each permission.
var minimumRole = map[Permission]Role{
	PermStateRead:     RoleViewer,
	PermUsageReadSelf: RoleViewer,

	PermInferenceUse: RoleUser,

	PermModelEnable:  RoleOperator,
	PermModelDisable: RoleOperator,
	PermModelRestart: RoleOperator,
	PermModelStage:   RoleOperator,
	PermNodeDrain:    RoleOperator,

	PermConfigWrite:     RoleAdmin,
	PermCatalogWrite:    RoleAdmin,
	PermBackendRegister: RoleAdmin,
	PermNodeApprove:     RoleAdmin,
	PermUserManage:      RoleAdmin,
	PermTokenManage:     RoleAdmin,
	PermPolicyApply:     RoleAdmin,
}

// ErrDenied is an authorization failure. It maps to docs/specs/10-cli.md §5's
// exit code 3.
var ErrDenied = errors.New("denied")

// Can reports whether r holds p.
//
// A permission with no entry is held by nobody, including an admin. Failing
// closed is the only safe direction: the alternative grants a newly named
// permission to whoever the map happens to omit.
func Can(r Role, p Permission) bool {
	min, known := minimumRole[p]
	if !known {
		return false
	}
	return r.rank() >= min.rank()
}

// Authorize returns ErrDenied naming the permission when r does not hold p.
//
// The message names the permission rather than the role, because "denied" with
// no subject is the error operators file bugs about.
func Authorize(r Role, p Permission) error {
	if Can(r, p) {
		return nil
	}
	if min, known := minimumRole[p]; known {
		return fmt.Errorf("%w: %s requires %s, and this is %s", ErrDenied, p, min, r)
	}
	return fmt.Errorf("%w: %s is not a permission this build grants", ErrDenied, p)
}

// joinWords renders a list as "a, b, c or d".
func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	head, tail := words[:len(words)-1], words[len(words)-1]
	s := ""
	for i, w := range head {
		if i > 0 {
			s += ", "
		}
		s += w
	}
	return s + " or " + tail
}
