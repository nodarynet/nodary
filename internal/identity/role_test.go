package identity

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEveryPermissionConstantHasAMinimumRole reads the source rather than the
// map, because reading the map would only prove the map agrees with itself.
//
// The failure it exists to catch is quiet: Can fails closed for a permission
// with no entry, so a constant added to the block below without a row in
// minimumRole compiles, reads correctly at every call site, and denies
// everybody including an admin.
func TestEveryPermissionConstantHasAMinimumRole(t *testing.T) {
	declared := declaredPermissions(t)
	if len(declared) < len(minimumRole) {
		t.Fatalf("found %d permission constants but the map has %d entries; the scan is wrong",
			len(declared), len(minimumRole))
	}
	for _, p := range declared {
		if _, ok := minimumRole[p]; !ok {
			t.Errorf("permission %q has no minimum role, so nobody holds it", p)
		}
	}
	for p := range minimumRole {
		if !contains(declared, p) {
			t.Errorf("minimumRole names %q, which is not a declared permission", p)
		}
	}
}

// declaredPermissions returns every `X Permission = "..."` constant in role.go.
func declaredPermissions(t *testing.T) []Permission {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "role.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing role.go: %v", err)
	}
	var out []Permission
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		typ := ""
		for _, s := range gen.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); ok {
				typ = id.Name
			}
			if typ != "Permission" || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquoting %s: %v", lit.Value, err)
			}
			out = append(out, Permission(v))
		}
	}
	if len(out) == 0 {
		t.Fatal("no permission constants found; the scan is broken, not the code")
	}
	return out
}

func contains(ps []Permission, want Permission) bool {
	for _, p := range ps {
		if p == want {
			return true
		}
	}
	return false
}

// TestOperatorRunsModelsAndDoesNotApproveNodes is R1-20's done: criterion,
// stated as the tracker states it.
func TestOperatorRunsModelsAndDoesNotApproveNodes(t *testing.T) {
	if !Can(RoleOperator, PermModelRestart) {
		t.Error("an operator must be able to restart a model")
	}
	if Can(RoleOperator, PermNodeApprove) {
		t.Error("an operator must not be able to approve a node")
	}
	if !Can(RoleAdmin, PermNodeApprove) {
		t.Error("an admin must be able to approve a node")
	}
}

// TestRolesAreCumulative is what docs/specs/07-identity-audit.md §1 means by
// "the above, plus": no role may hold something a stronger role does not.
func TestRolesAreCumulative(t *testing.T) {
	for i := 1; i < len(Roles); i++ {
		weak, strong := Roles[i-1], Roles[i]
		for p := range minimumRole {
			if Can(weak, p) && !Can(strong, p) {
				t.Errorf("%s holds %s but %s does not", weak, p, strong)
			}
		}
	}
}

func TestEachRoleHoldsStrictlyMore(t *testing.T) {
	count := func(r Role) int {
		n := 0
		for p := range minimumRole {
			if Can(r, p) {
				n++
			}
		}
		return n
	}
	for i := 1; i < len(Roles); i++ {
		if a, b := count(Roles[i-1]), count(Roles[i]); a >= b {
			t.Errorf("%s holds %d permissions and %s holds %d; each role must add something",
				Roles[i-1], a, Roles[i], b)
		}
	}
	if n := count(RoleAdmin); n != len(minimumRole) {
		t.Errorf("admin holds %d of %d permissions; §1 says everything", n, len(minimumRole))
	}
}

// TestAnUnknownPermissionIsHeldByNobody fixes the direction of the failure. The
// alternative — an unknown permission being granted — hands a newly named
// capability to whoever the map happens to omit.
func TestAnUnknownPermissionIsHeldByNobody(t *testing.T) {
	for _, r := range append(Roles, Role("")) {
		if Can(r, Permission("node.detonate")) {
			t.Errorf("%q holds an unknown permission", r)
		}
	}
	err := Authorize(RoleAdmin, Permission("node.detonate"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Authorize error = %v, want ErrDenied", err)
	}
	if !strings.Contains(err.Error(), "node.detonate") {
		t.Errorf("error does not name the permission: %v", err)
	}
}

// TestAnInvalidRoleHoldsNothing covers a corrupted or unset column. rank uses
// slices.Index, which returns -1 for a miss, so an unrecognised role must land
// below viewer rather than at it.
func TestAnInvalidRoleHoldsNothing(t *testing.T) {
	for _, r := range []Role{"", "root", "Admin", "ADMIN", "superuser"} {
		if r.Valid() {
			t.Errorf("%q reported as a valid role", r)
		}
		if Can(r, PermStateRead) {
			t.Errorf("%q holds the weakest permission", r)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range Roles {
		got, err := ParseRole(string(r))
		if err != nil || got != r {
			t.Errorf("ParseRole(%q) = %q, %v", r, got, err)
		}
	}
	_, err := ParseRole("Admin")
	if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("ParseRole(\"Admin\") error = %v, want ErrUnknownRole", err)
	}
	for _, want := range []string{"viewer", "user", "operator", "admin", "Admin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q: %v", want, err)
		}
	}
}

func TestAuthorizeNamesWhatIsMissing(t *testing.T) {
	err := Authorize(RoleOperator, PermNodeApprove)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	for _, want := range []string{"node.approve", "admin", "operator"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q: %v", want, err)
		}
	}
	if err := Authorize(RoleOperator, PermModelRestart); err != nil {
		t.Errorf("Authorize(operator, model.restart) = %v, want nil", err)
	}
}

// TestTheRoleTableIsWhatSection1Says transcribes
// docs/specs/07-identity-audit.md §1's table and pins it whole.
//
// Without it, moving a permission one tier up or down survives every other test
// here: the cumulative and strictly-more checks only constrain the shape of the
// ordering, not which row a capability sits in, so `state.read` could quietly
// leave the viewer row and nothing would fail.
func TestTheRoleTableIsWhatSection1Says(t *testing.T) {
	// "Read state; read own usage"
	viewer := []Permission{PermStateRead, PermUsageReadSelf}
	// "The above, plus use the inference API"
	user := append(slices.Clone(viewer), PermInferenceUse)
	// "The above, plus enable, disable and restart models; stage weights;
	// drain nodes"
	operator := append(slices.Clone(user),
		PermModelEnable, PermModelDisable, PermModelRestart, PermModelStage, PermNodeDrain)
	// "Everything: configuration, catalog and backend registration, node
	// approval, user and token management, policy"
	admin := append(slices.Clone(operator),
		PermConfigWrite, PermCatalogWrite, PermBackendRegister, PermNodeApprove,
		PermUserManage, PermTokenManage, PermPolicyApply)

	want := map[Role][]Permission{
		RoleViewer: viewer, RoleUser: user, RoleOperator: operator, RoleAdmin: admin,
	}
	for role, held := range want {
		for p := range minimumRole {
			expect := slices.Contains(held, p)
			if got := Can(role, p); got != expect {
				t.Errorf("Can(%s, %s) = %v, want %v", role, p, got, expect)
			}
		}
	}
}
