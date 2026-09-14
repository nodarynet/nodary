package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
)

// cmdModelStageReset is `model unstage` and `model restage` — both are the
// same underlying request, "discard what this node has for this model and
// let it re-stage from nothing" (internal/agent/remote.go's Downloader.Reset,
// R4-35/R4-36), told apart only by which precondition guards it.
//
// **`unstage` requires no deployment on this node still wants the model** —
// deleting weights out from under a live deployment is exactly the accident
// that precondition exists to prevent. **`restage` requires the observed
// state to be `corrupt`** — docs/specs/05-catalog.md §3 makes that state the
// one an explicit restage is for, not a general "redownload even though it's
// fine" button that could yank weights out from under a healthy deployment.
// And `restage` refuses `source: local` outright: VerifyStaged re-reads
// every byte from disk on every reconcile already, so there is nothing
// cached to reset — an operator whose media has a bad file needs to replace
// that file, not have nodary erase all of them.
//
// Neither writes to config.Snapshot, so neither calls config.Record: the
// request lives in its own table (`stage_reset`), consumed by the agent and
// acknowledged over the heartbeat (internal/observed.Heartbeat), the same
// shape join-token redemption already uses for a one-shot request the
// protocol's "no imperative commands" rule (docs/specs/03-agent.md §2) has
// no other way to express.
func cmdModelStageReset(e env, args []string, verb string) int {
	fs := newFlagSet(e, "model "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	node := fs.String("node", "", "the node whose copy this affects")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary model %s: expected one model id\n", verb)
		return ExitUsage
	}
	if *node == "" {
		fmt.Fprintf(e.stderr, "nodary model %s: --node is required; `nodary node list` names them\n", verb)
		return ExitUsage
	}
	id := fs.Arg(0)

	rem, code := remoteFor(e, "model "+verb, *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if rem != nil {
		// --node is required on this side and narrows on the far side too: a
		// flag accepted here and dropped on the wire would turn "discard the
		// copy on gpu-02" into a request against whichever node the control
		// plane picked.
		_, applied, code := rem.attested(e, "model "+verb, remoteAct{method: "POST",
			path: addQuery("/models/"+url.PathEscape(id)+"/"+verb, "node="+url.QueryEscape(*node))},
			cer, *format)
		if !applied {
			return code
		}
		notePoll(e, verb, id, *node)
		return ExitOK
	}

	s, ok := openSession(e, "model "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	rec, applied, code := s.attested(e, "model "+verb, change{
		action: "model." + verb,
		target: &audit.Target{Kind: "model", ID: id},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			return fleet.StageResetPreview(ctx, tx, verb, id, *node)
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermModelStage); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			return fleet.RequestStageReset(context.Background(), m, s.now, id, *node)
		},
	}, cer, *format)
	if !applied {
		return code
	}

	notePoll(e, verb, id, *node)
	reportRecord(e, rec)
	return ExitOK
}

// notePoll says when the request takes effect. The agent pulls; nothing here
// pushes (docs/specs/03-agent.md §1), so "done" means "recorded", and an
// operator watching `node show` for an immediate change needs to know that.
func notePoll(e env, verb, id, node string) {
	fmt.Fprintf(e.stderr, "model %s: %s on %s will be applied on the agent's next poll (up to 60s)\n",
		verb, id, node)
}
