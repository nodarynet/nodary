package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/derive"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// DerivePlan is one backend resolved to a build that may proceed:
// dev/specs/04-backends.md §5's refusals have all been made, before half an
// hour of an operator's time is spent rather than after it.
//
// It lives here, and not in either front end, because `nodary backend build`
// and `POST /backends/{name}/build` run the same sequence. internal/api's own
// doc comment says a handler that decided anything would be the second
// implementation this arrangement exists to prevent — and a refusal one front
// end makes and the other does not is exactly that.
type DerivePlan struct {
	Name       string
	Descriptor backend.Descriptor
	// Recipe is the digest of the inputs. The tag carries it, the record
	// stores it, and staleness is measured against it.
	Recipe string
	// Tag is a handle, not what anything pins: deployments pin the digest, so
	// a rebuild of an unchanged recipe may reuse this tag without moving
	// anything that is serving.
	Tag string
	// Previous is the image a rebuild replaces, nil when nothing is built.
	// Read before the build so a refusal can name what is already there.
	Previous *backend.Built
}

// PlanDerive resolves a backend to a build, or refuses.
//
// `rebuild` is §5's "a derived image is built once; rebuilding is explicit":
// a `build` that quietly rebuilt would be the silent change the audit chain
// exists to prevent, so the second one has to be asked for by another name.
func PlanDerive(ctx context.Context, q Querier, active policy.Profile, name string, rebuild bool) (DerivePlan, error) {
	d, err := BackendFor(ctx, q, name)
	if err != nil {
		// backend.ErrUnknown is in neither front end's error table, so it
		// would be exit 1 on one side and a 500 on the other. Named as what
		// it is: the thing does not exist.
		return DerivePlan{}, fmt.Errorf("%w: %v", identity.ErrNotFound, err)
	}
	if d.Backend.Derive == nil {
		return DerivePlan{}, fmt.Errorf("%w: %s is not a derived image; there is no recipe to "+
			"build. A derive declares [backend.derive] and inherits a built-in "+
			"(dev/specs/04-backends.md §5)", ErrInvalid, name)
	}

	// Checked here as well as at registration, because a profile can be
	// tightened afterwards: a site that moved to `regulated` last week must not
	// still be able to build the unpinned recipe it registered before, or the
	// flag would be advice rather than a control.
	if !active.AllowDerivedImages {
		return DerivePlan{}, fmt.Errorf("%w: the %s profile does not allow derived images",
			ErrInvalid, active.Name)
	}
	if active.RequirePinnedDerives {
		if err := d.Backend.Derive.Pinned(); err != nil {
			return DerivePlan{}, fmt.Errorf("%w: %v. The %s profile sets "+
				"require_pinned_derives, so a build has to be reproducible rather than "+
				"merely recorded (dev/specs/04-backends.md §5)", ErrInvalid, err, active.Name)
		}
	}

	have, err := BuiltImage(ctx, q, name)
	if err != nil {
		return DerivePlan{}, err
	}
	if have != nil {
		have.Staleness(d.Backend.Derive)
		if !rebuild {
			why := "it is already built"
			if have.Stale {
				why = have.Why
			}
			return DerivePlan{}, fmt.Errorf("%w: %s has an image already (%s): %s. A rebuild "+
				"replaces it; deployments already pinned to the previous digest keep serving "+
				"until they are re-registered", ErrInvalid, name, have.Digest, why)
		}
	}

	recipe := d.Backend.Derive.RecipeSHA256()
	return DerivePlan{
		Name: name, Descriptor: d, Recipe: recipe, Previous: have,
		Tag: fmt.Sprintf("nodary/%s:%s", name, recipe[:12]),
	}, nil
}

// DerivePreview is the change an operator approves, read from the transaction
// so that `replaces` is what is on record at the moment of the act.
//
// **The digest the build produced is not in it, and that is the whole of what
// the intent hash can be.** A preview has to render the same twice — once to
// show and hash, once inside the transaction to bind — and over HTTP those two
// are separate requests, so anything the build itself decided would differ
// between them and refuse every act with a 412. What can legitimately move
// between a preview and an apply is what is already built, and that stays.
// §5's requirement that the record carry the image and its digest is met by
// the audit details RecordDerive writes, which is where it was always met.
func DerivePreview(p DerivePlan, prev *backend.Built) map[string]any {
	out := map[string]any{
		"backend": p.Name, "base": p.Descriptor.Backend.Derive.From,
		"recipe_sha256": p.Recipe, "replaces": "",
	}
	if prev != nil {
		out["replaces"] = prev.Digest
	}
	return out
}

// RecordDerive writes what a build produced: §5's actual requirement is the
// inputs pinned, the output pinned, and the person who asked for it named.
// Actor and justification are already in the record; these are the rest.
func RecordDerive(ctx context.Context, m audit.Mutation, now time.Time, actor string,
	p DerivePlan, res derive.Result) error {

	m.Detail("recipe_sha256", p.Recipe)
	m.Detail("base_digest", p.Descriptor.Backend.Derive.From)
	m.Detail("image", res.Image)
	m.Detail("image_digest", res.Digest)
	m.Detail("steps", res.Steps)
	if len(res.Reached) > 0 {
		m.Detail("reached", strings.Join(res.Reached, ", "))
	}

	stamp := now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat)
	_, err := m.Tx().ExecContext(ctx, `INSERT INTO derived_image
		(name, recipe_sha256, base_digest, image, digest, built_at, built_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET
			recipe_sha256 = excluded.recipe_sha256, base_digest = excluded.base_digest,
			image = excluded.image, digest = excluded.digest,
			built_at = excluded.built_at, built_by = excluded.built_by`,
		p.Name, p.Recipe, p.Descriptor.Backend.Derive.From, res.Image, res.Digest,
		stamp, actor)
	return err
}
