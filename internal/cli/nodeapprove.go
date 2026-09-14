package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdNodeTransition is `node approve` and `node drain`.
//
// **The install tells the operator to run this.** `node install` closes with
// "It is pending and will receive no work until an administrator runs `nodary
// node approve <name>`", and that verb was a stub — approval existed only over
// the HTTP API, which on a single box means an administrator account, a token,
// and curl, to move a machine that is already sitting there. Found the first
// time a model was deployed: everything applied, the node stayed `pending`, and
// `agent plan` correctly showed nothing to do.
//
// It builds the same change the API's handler does rather than a second one.
// The preview carries the node's advertised offer and constraints because that
// is what the administrator is agreeing to, and core.Act hashes the preview
// into `intent_hash` — which is how docs/specs/02-enrollment.md §1's "neither
// side can later claim terms the other did not see" is structural rather than
// prose.
func cmdNodeTransition(e env, args []string, verb, to string) int {
	fs := newFlagSet(e, "node "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary node %s: expected one node name\n", verb)
		return ExitUsage
	}
	name := fs.Arg(0)

	r, code := remoteFor(e, "node "+verb, *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if r != nil {
		// The same ceremony and the same record, written by the control plane
		// against the person holding the credential rather than against
		// whoever has root on that machine. That is the whole of why this flag
		// exists: `node approve` is the act 02 §1 builds its agreement out of,
		// and a chain answering "who approved this node" with `root` describes
		// nothing.
		out, applied, code := r.attested(e, "node "+verb, remoteAct{
			method: "POST", path: "/nodes/" + url.PathEscape(name) + "/" + verb}, cer, *format)
		if !applied {
			return code
		}
		fmt.Fprintf(e.stderr, "node %s: %s -> %s\n", name, orDash(previewString(out.Change, "from")), to)
		// The credential names a real account, which is the difference this
		// flag is for: the "approved locally, so the row names no approver"
		// note below is never the right thing to print over --server.
		reportTransition(e, verb, to, name, r.cred.User)
		reportRecord(e, audit.Record{Seq: out.AuditSeq})
		return ExitOK
	}

	s, ok := openSession(e, "node "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var from string
	rec, applied, code := s.attested(e, "node "+verb, change{
		action: "node." + verb,
		target: &audit.Target{Kind: "node", ID: name},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			preview, err := fleet.TransitionPreview(ctx, tx, name, to)
			if err != nil {
				return nil, err
			}
			from, _ = preview["from"].(string)
			return preview, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, fleet.Permission(to)); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			if err := fleet.Transition(context.Background(), m, s.now, name, to, s.who.User.ID); err != nil {
				return err
			}
			// `node.state` is in the configuration snapshot, so this is a
			// configuration change and records a revision like any other.
			// Without it the chain has a hole — and because the agent's
			// long-poll compares against that sequence, **an approved node
			// would not learn it had been approved** until something unrelated
			// moved the counter.
			_, err := config.Record(context.Background(), m, s.now, s.who.Actor.ID, *cer.justify)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr, "node %s: %s -> %s\n", name, from, to)
	reportTransition(e, verb, to, name, s.who.User.ID)
	reportRecord(e, rec)
	return ExitOK
}

// reportTransition is what to expect now, and both routes print it.
//
// None of it is obvious and all of it is already built, so an operator who has
// just ejected a node or approved one should not have to go and read a spec to
// find out what happens next.
func reportTransition(e env, verb, to, name, actorUserID string) {
	if verb == "revoke" {
		// What actually happens now, because none of it is obvious and all of
		// it is already built: docs/specs/02-enrollment.md §3 refuses the
		// certificate on next contact (internal/api's agentNode), a node that
		// is not approved receives an empty desired state and so stops
		// everything within a poll, and the gateway stops routing to it
		// (internal/gateway's ConfigFor).
		fmt.Fprintf(e.stderr,
			"  Its certificate is refused from now on, it stops serving within a poll,\n"+
				"  and its deployments leave their routes on the next `nodary gateway sync`.\n"+
				"  Its history is kept. Rejoining is a fresh enrollment.\n")
	}
	if to == "approved" {
		fmt.Fprintf(e.stderr, "  It will receive its desired state on the agent's next poll.\n")
		if actorUserID == "" {
			fmt.Fprintf(e.stderr,
				"  Approved locally, so the node row names no approver; the chain records who and when.\n")
		}
		// The next step, named. An approved node with nothing placed on it is
		// idle, healthy and indistinguishable from a broken one — and this verb
		// was where every printed instruction in the product ran out.
		fmt.Fprintf(e.stderr,
			"\nNothing is placed on it yet. With weights staged under %s:\n"+
				"  nodary model register <org/name> --node %s --gpu 0 --port 8001\n",
			agent.DefaultModelsDir(), name)
	}
}

// previewString reads one field out of a preview the control plane rendered.
func previewString(preview map[string]any, field string) string {
	v, _ := preview[field].(string)
	return v
}
