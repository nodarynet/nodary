package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdPolicy(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary policy: expected a subcommand (show, apply, diff)\n")
		return ExitUsage
	}
	switch args[0] {
	case "show":
		return cmdPolicyShow(e, args[1:])
	case "apply":
		return cmdPolicyApply(e, args[1:])
	case "diff":
		return cmdPolicyDiff(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary policy: unknown subcommand %q (want show, apply or diff)\n", args[0])
	return ExitUsage
}

// loadCandidate resolves a profile argument, which is either the name of a
// built-in profile or a path to a TOML file.
//
// Names win over paths. A file called `regulated` in the working directory
// silently displacing the shipped profile is the kind of surprise a posture
// object must not have, and `./regulated` still reaches the file.
func loadCandidate(e env, verb, arg string) (policy.Profile, []byte, bool) {
	if slices.Contains(policy.BuiltinNames(), arg) {
		p, src, err := policy.Builtin(arg)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return policy.Profile{}, nil, false
		}
		return p, src, true
	}

	src, err := os.ReadFile(arg)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		fmt.Fprintf(e.stderr, "  expected a built-in profile (%s) or a path to a TOML file\n",
			strings.Join(policy.BuiltinNames(), ", "))
		return policy.Profile{}, nil, false
	}
	p, err := policy.Parse(src)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return policy.Profile{}, nil, false
	}
	return p, src, true
}

// activeProfile reads the profile in force without opening the database for
// writing, so `show` and `diff` work against a read-only copy.
func activeProfile(e env, verb string, rem *remote, dbPath string) (policy.Profile, bool) {
	var p policy.Profile
	var err error
	if rem != nil {
		// GET /policy answers with the profile itself, so the far side's
		// policy.Active is the only reader of the row either way.
		_, err = rem.get("/policy", &p)
	} else {
		var db *store.DB
		if db, err = store.OpenReadOnly(context.Background(), dbPath); err == nil {
			defer db.Close()
			p, _, err = policy.Active(context.Background(), db.Read())
		}
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return policy.Profile{}, false
	}
	return p, true
}

// reportLoosens is 07 §4's rule: loosening is permitted, doing it silently is
// not. To stderr and before the change, so it is visible even when stdout is
// being parsed as JSON — and shared by both routes, because a posture relaxed
// without saying so over the network is the same failure as locally.
func reportLoosens(e env, active, candidate policy.Profile) {
	for _, c := range policy.Diff(active, candidate) {
		if c.Loosens {
			fmt.Fprintf(e.stderr, "loosens: %s\n", c)
		}
	}
}

func cmdPolicyShow(e env, args []string) int {
	fs := newFlagSet(e, "policy show")
	format := formatFlag(fs)
	dbPath, _, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rem, code := remoteFor(e, "policy show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	p, ok := activeProfile(e, "policy show", rem, *dbPath)
	if !ok {
		return ExitFailure
	}

	if *format == "json" {
		// The profile and what acts on it, side by side. A caveat carried only
		// by the text renderer would be missing from the one form somebody
		// pastes into a system security plan.
		return writeJSON(e, "policy show", struct {
			policy.Profile
			Standing map[string]string `json:"standing"`
		}{p, policy.Standing()})
	}
	fmt.Fprintf(e.stdout, "%s\n", p.Name)
	for _, l := range policy.Describe(p) {
		fmt.Fprintf(e.stdout, "  %s\n", l)
	}
	if n := len(policy.Unenforced()); n > 0 {
		fmt.Fprintf(e.stderr,
			"\n%d of these are not enforced yet; each names the task that will enforce it.\n", n)
	}
	return ExitOK
}

func cmdPolicyDiff(e env, args []string) int {
	fs := newFlagSet(e, "policy diff")
	format := formatFlag(fs)
	dbPath, _, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary policy diff: expected one profile (a built-in name or a TOML file)\n")
		return ExitUsage
	}
	rem, code := remoteFor(e, "policy diff", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	// Client-side on both routes, for the reason `config diff` is: policy.Diff
	// is a pure function of two profiles, so a diff endpoint would be a second
	// implementation of it with one caller — and the candidate is a file on
	// this machine the control plane cannot read. What crosses is the active
	// profile.
	active, ok := activeProfile(e, "policy diff", rem, *dbPath)
	if !ok {
		return ExitFailure
	}
	candidate, _, ok := loadCandidate(e, "policy diff", fs.Arg(0))
	if !ok {
		return ExitUsage
	}

	changes := policy.Diff(active, candidate)
	if *format == "json" {
		return writeJSON(e, "policy diff", map[string]any{
			"active": active.Name, "candidate": candidate.Name,
			"changes": changes, "loosens": policy.Loosens(changes),
		})
	}
	if len(changes) == 0 {
		fmt.Fprintf(e.stdout, "no change: %s and %s are identical\n", active.Name, candidate.Name)
		return ExitOK
	}
	fmt.Fprintf(e.stdout, "%s -> %s\n", active.Name, candidate.Name)
	for _, c := range changes {
		fmt.Fprintf(e.stdout, "  %s\n", c)
	}
	if policy.Loosens(changes) {
		fmt.Fprintf(e.stderr, "\nthis profile loosens the posture; the lines marked (loosens) say where\n")
	}
	return ExitOK
}

func cmdPolicyApply(e env, args []string) int {
	fs := newFlagSet(e, "policy apply")
	format := formatFlag(fs)
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary policy apply: expected one profile (a built-in name or a TOML file)\n")
		return ExitUsage
	}
	rem, code := remoteFor(e, "policy apply", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}

	// Parsed here on both routes, which is not a second implementation: a
	// malformed file is the operator's own, on the operator's own machine, and
	// saying so without a round trip is the difference between a typo and a
	// failed request. What travels is the bytes, so the control plane parses
	// them itself before applying — the same argument `config apply` sends
	// TOML on.
	candidate, source, ok := loadCandidate(e, "policy apply", fs.Arg(0))
	if !ok {
		return ExitUsage
	}

	if rem != nil {
		return policyApplyRemote(e, rem, candidate, source, fs.Arg(0), cer, *format, *dbPath)
	}

	s, ok := openSession(e, "policy apply", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	active, _, err := policy.Active(context.Background(), s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary policy apply: %v\n", err)
		return ExitFailure
	}

	changes := policy.Diff(active, candidate)
	reportLoosens(e, active, candidate)

	rec, applied, code := s.attested(e, "policy apply", change{
		action: "policy.apply",
		target: &audit.Target{Kind: "policy", ID: candidate.Name},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The diff, not the candidate: the posture this replaces is what
			// moves if another administrator applies something in between, and
			// an operator who approved "regulated over default" did not approve
			// "regulated over whatever is there now".
			from, _, err := policy.Active(ctx, tx)
			if err != nil {
				return nil, err
			}
			d := policy.Diff(from, candidate)
			lines := make([]string, len(d))
			for i, c := range d {
				lines[i] = c.String()
			}
			// What this profile would deny that is already registered. In the
			// preview, so it is part of what the operator attests to rather
			// than a warning printed after the decision — docs/specs/05-catalog.md
			// §2 flags these rather than stopping them, and a flag nobody is
			// shown at the moment of the change is not a flag.
			denied, err := config.Denied(ctx, tx, candidate)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"from": from.Name, "to": candidate.Name, "changes": lines}
			if len(denied) > 0 {
				out["denies"] = denied
			}
			return out, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			if err := policy.Apply(context.Background(), m, s.who.Role, s.now, candidate, source); err != nil {
				return err
			}
			// The active profile is part of the configuration snapshot, so
			// changing it is a configuration change and records a revision.
			// R2-11: every configuration change writes one.
			_, err := config.Record(context.Background(), m, s.now, s.who.Actor.ID, *cer.justify)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	reportDenied(e, s, candidate)

	if *format == "json" {
		return writeJSON(e, "policy apply", map[string]any{
			"profile": candidate.Name, "changes": changes,
			"loosens": policy.Loosens(changes), "record": rec.Seq,
		})
	}
	fmt.Fprintf(e.stdout, "applied %s (%d %s)\n", candidate.Name,
		len(changes), plural("change", len(changes)))
	fmt.Fprintf(e.stderr, "recorded as audit record %d\n", rec.Seq)
	return ExitOK
}

// policyApplyRemote is the same act against a control plane over the network.
//
// The profile travels as a **name when it is a built-in and as bytes when it is
// a file**, because those are two different acts: a built-in is a thing the far
// side already has and can name in its own records, and a file is a document
// this machine holds that the control plane has never seen. Sending the parsed
// profile instead would make this side's reading of the document the one that
// gets applied, which is the divergence `config apply` sends raw TOML to avoid.
func policyApplyRemote(e env, rem *remote, candidate policy.Profile, source []byte,
	arg string, cer ceremonyFlags, format, dbPath string) int {
	active, ok := activeProfile(e, "policy apply", rem, dbPath)
	if !ok {
		return ExitFailure
	}
	changes := policy.Diff(active, candidate)
	reportLoosens(e, active, candidate)

	body := map[string]string{"source": string(source)}
	if slices.Contains(policy.BuiltinNames(), arg) {
		body = map[string]string{"profile": arg}
	}
	out, applied, code := rem.attested(e, "policy apply", remoteAct{
		method: "POST", path: "/policy/apply", body: body}, cer, format)
	if !applied {
		return code
	}

	// The far side computed this against its own catalog while applying, and
	// sends it back rather than leaving an operator to run a second command to
	// find out what their change now refuses. Reading it from the database is
	// not an option here: the catalog is on the other machine.
	var denied []config.DeniedModel
	if raw, err := json.Marshal(out.Result["denies"]); err == nil {
		_ = json.Unmarshal(raw, &denied)
	}
	renderDenied(e, candidate.Name, denied)

	if format == "json" {
		return writeJSON(e, "policy apply", map[string]any{
			"profile": candidate.Name, "changes": changes,
			"loosens": policy.Loosens(changes), "record": out.AuditSeq,
		})
	}
	fmt.Fprintf(e.stdout, "applied %s (%d %s)\n", candidate.Name,
		len(changes), plural("change", len(changes)))
	fmt.Fprintf(e.stderr, "recorded as audit record %d\n", out.AuditSeq)
	return ExitOK
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// reportDenied names what the profile just applied refuses and is still
// serving.
//
// **Flagged, not stopped** (docs/specs/11-failure-modes.md). Nothing here stops
// anything: it says what an operator would have to decide, and names the verb
// that decides it, because a model pulled out from under its users by a policy
// edit is exactly the surprise this rule exists to prevent.
func reportDenied(e env, s *session, p policy.Profile) {
	denied, err := config.Denied(context.Background(), s.db.Read(), p)
	if err != nil {
		return
	}
	renderDenied(e, p.Name, denied)
}

// renderDenied is the rendering both routes share. Locally the list is read
// from the database; over the network it arrives in the applied response,
// computed by the machine that has the catalog.
func renderDenied(e env, profile string, denied []config.DeniedModel) {
	if len(denied) == 0 {
		return
	}
	fmt.Fprintf(e.stderr, "\n%s now denies %d already-registered %s. Nothing was stopped:\n",
		profile, len(denied), plural("model", len(denied)))
	for _, d := range denied {
		serving := "not deployed"
		if len(d.Deployments) > 0 {
			serving = "serving as " + strings.Join(d.Deployments, ", ")
		}
		fmt.Fprintf(e.stderr, "  %s — origin %s, %s\n", d.ID, d.Origin, serving)
	}
	fmt.Fprintf(e.stderr, "  Stopping one is your decision and is audited: `nodary model disable <id>`.\n")
}
