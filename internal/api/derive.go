package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/core"
	"github.com/nodarynet/nodary/internal/derive"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// buildDerive and buildRuntime are swapped in a test, the way internal/cli
// swaps its own. What this endpoint decides — who may build, what a second
// build means, and the record it writes — is the part worth testing, and none
// of it needs a container runtime, which a test has not got.
var (
	buildDerive  = derive.Build
	buildRuntime = derive.Exec
)

// buildBackend is POST /backends/{name}/build — dev/specs/04-backends.md §5.
//
// **Synchronous, because the alternative cannot attest.** A 202 and a poll
// would have to record the act when the build finishes, which means the
// justification an operator gave approves a recipe rather than a result, and
// the CLI would be attesting a different claim from this — the divergence this
// package's doc comment says the arrangement exists to prevent. So the request
// is held for the build, bounded by the recipe's own `timeout_s`.
//
// **The build runs before core.Act, not inside it**, for internal/cli's
// reason: core.Act performs a change inside the audit transaction, so building
// there would hold a write lock on the whole control plane while every node's
// heartbeat queued behind it.
//
// `?rebuild=true` is §5's "a derived image is built once; rebuilding is
// explicit", spelled the way `?node=` is on enable and disable rather than as
// a second path — it is one act with one permission and one record, and the
// flag is which of two things the operator meant.
func (s *Server) buildBackend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	rebuild := r.URL.Query().Get("rebuild") == "true"
	verb := "build"
	if rebuild {
		verb = "rebuild"
	}

	p, err := s.principalOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Refused before the build rather than after it: half an hour of work and
	// then "you may not do that" is a refusal that arrives too late to be one.
	// Checked again inside Apply, where every other mutation checks it.
	if err := identity.Authorize(p.Role, identity.PermBackendRegister); err != nil {
		s.fail(w, r, err)
		return
	}

	ctx := r.Context()
	active, _, err := policy.Active(ctx, s.db.Read())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	plan, err := config.PlanDerive(ctx, s.db.Read(), active, name, rebuild)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// **A dry run does not build.** The rendered change is the recipe and the
	// image it replaces, neither of which the build decides, so a preview that
	// built would spend the whole timeout to learn what it already knows — and
	// the hash it returned would be the same one. That is what makes preview →
	// intent_hash → apply usable here at all: without it the confirm would have
	// to build a second time to re-render, and an unpinned recipe producing a
	// different digest would refuse its own approval with a 412.
	var built derive.Result
	if r.URL.Query().Get("dry_run") != "true" {
		if built, err = buildDerive(ctx, derive.Options{
			Descriptor: plan.Descriptor, Tag: plan.Tag, Run: buildRuntime,
		}); err != nil {
			s.fail(w, r, err)
			return
		}
		// **Exported before the ceremony, for the build's own reason.** A node
		// can neither build this image nor pull it — it is committed here and
		// pushed nowhere — so §5's "served to nodes like any other image"
		// needs it in the cache the mirror serves. A tar nothing references
		// yet is the same category as the image in the content store nothing
		// references yet: if the act is refused, neither is adopted and
		// neither is reachable.
		tarball := filepath.Join(s.dist, DerivedImageFile(built.Digest))
		if err := derive.Export(ctx, buildRuntime, built.Digest, tarball); err != nil {
			s.fail(w, r, fmt.Errorf("the image was built, and without the export a node "+
				"cannot fetch it, so nothing is recorded: %w", err))
			return
		}
	}

	s.mutate(w, r, core.Change{
		Action: "backend." + verb,
		Target: &audit.Target{Kind: "backend", ID: name},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The previous row is read from the transaction, so a build that
			// raced another one is refused by the intent hash rather than
			// overwriting a record of what is serving.
			prev, err := config.BuiltImage(ctx, tx, name)
			if err != nil {
				return nil, err
			}
			return config.DerivePreview(plan, prev), nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(p.Role, identity.PermBackendRegister); err != nil {
				return err
			}
			if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
				return err
			}
			return config.RecordDerive(context.Background(), m, s.now(), p.Actor.ID, plan, built)
		},
	}, func(core.Outcome) any {
		// The digest is not in the preview and so not in the intent hash, but
		// it is what the caller asked for. §5's record of it is the audit
		// detail RecordDerive writes; this is the answer to the request.
		return map[string]any{
			"image": built.Image, "digest": built.Digest, "steps": built.Steps,
		}
	})
}

// showBuild is GET /backends/{name}/build — what is built for this backend.
//
// Deliberately a projection of what GET /backends/{name} already carries,
// rather than a second reader: §5's staleness is derived from the recipe in
// force, and two places deriving it is two places to get it wrong. Its own
// path because a UI polling a build wants this and not the whole descriptor.
//
// A backend that is not a derive answers with nulls rather than refusing.
// "What is built for vllm" has an honest answer — nothing, and there is no
// recipe — and a read that refuses to give it buys nothing.
func (s *Server) showBuild(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		name := r.PathValue("name")
		rep, err := config.BackendReport(r.Context(), d.DB.Read(), name)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", identity.ErrNotFound, err)
		}
		return map[string]any{
			"backend": rep.Name, "recipe": rep.Recipe, "built": rep.Built,
		}, nil
	})
}
