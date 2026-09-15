package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/derive"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/policy"
)

// buildDerive is swapped in a test. What this verb decides — who may build,
// what a second build means, and the record it writes — is the part worth
// testing, and none of it needs a container runtime, which a test has not got.
var buildDerive = derive.Build

// buildRuntime is how the export reaches nerdctl, swapped in a test alongside
// buildDerive. Separate from it because a stubbed build still has to leave the
// export a real code path to run.
var buildRuntime derive.Runner = runNerdctl

// cmdBackendBuild is `nodary backend build` and `rebuild` — dev/specs/04-backends.md §5.
//
// **The build runs before the ceremony, and the ceremony is what adopts it.**
// A build takes up to `timeout_s`, which §5's own example sets to half an hour,
// and internal/core.Act performs a change *inside* the audit transaction — so
// building there would hold a write lock on the whole control plane while every
// node's heartbeat queued behind it. Instead the build happens first, changing
// nothing nodary knows about, and the attested act records what it produced.
// That also gives the intent hash something better to bind: the operator
// approves the digest that was actually built, not a promise to build one.
//
// The permission is backend registration's. 07 §1 gives admin "the catalog and
// backend registration" as one area, and a `backend.build` permission mapped to
// the same role would be vocabulary with no decision inside it.
//
// **`--server` forwards the whole act, it does not build here.** §5 puts a
// build on the control plane, so an operator at a laptop is asking the control
// plane to build — the image, the mirror it is exported to and the runtime that
// produced it all live there, and a build run locally would leave the result on
// the wrong machine. What crosses the wire is the request and the attestation.
//
// It works because a preview does not build (internal/api's buildBackend says
// why): `attested` renders remotely first to get the hash, and a preview that
// built would spend the recipe's whole timeout twice for one image.
func cmdBackendBuild(e env, args []string, verb string) int {
	fs := newFlagSet(e, "backend "+verb)
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	distDir := fs.String("dist", "", "the component cache the mirror serves; defaults to "+
		filepath.Join(paths.DataDir, api.DistDirName))
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary backend %s: expected one backend name\n", verb)
		return ExitUsage
	}
	name := fs.Arg(0)

	rem, code := remoteFor(e, "backend "+verb, *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if rem != nil {
		path := "/backends/" + url.PathEscape(name) + "/build"
		if verb == "rebuild" {
			path = addQuery(path, "rebuild=true")
		}
		// Said rather than ignored, the way `config apply --no-sync` says it:
		// the mirror a build exports to is a directory on the control-plane
		// host, and this machine cannot write it.
		if *distDir != "" {
			fmt.Fprintf(e.stderr, "--dist has no effect over --server: the image is exported "+
				"to the\ncontrol plane's own component cache.\n")
		}
		out, applied, code := rem.attested(e, "backend "+verb,
			remoteAct{method: "POST", path: path}, cer, *format)
		if !applied {
			return code
		}
		digest, _ := out.Result["digest"].(string)
		fmt.Fprintf(e.stderr,
			"\n%s is %s. `nodary model register --backend %s` pins it into a deployment;\n"+
				"deployments already on a previous digest keep serving until they are "+
				"re-registered.\n", name, digest, name)
		reportRecord(e, audit.Record{Seq: out.AuditSeq})
		return ExitOK
	}

	s, ok := openSession(e, "backend "+verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	ctx := context.Background()
	// Refused before the build rather than after it: half an hour of work and
	// then "you may not do that" is a refusal that arrives too late to be one.
	// The permission is backend registration's. 07 §1 gives admin "the catalog
	// and backend registration" as one area, and a `backend.build` permission
	// mapped to the same role would be vocabulary with no decision inside it.
	if err := identity.Authorize(s.who.Role, identity.PermBackendRegister); err != nil {
		fmt.Fprintf(e.stderr, "nodary backend %s: %v\n", verb, err)
		return ExitPolicy
	}
	active, _, err := policy.Active(ctx, s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backend %s: %v\n", verb, err)
		return ExitFailure
	}
	// Every refusal §5 owes an operator, made in one place both front ends
	// call, so `backend build` and POST /backends/{name}/build cannot disagree
	// about what may be built.
	plan, err := config.PlanDerive(ctx, s.db.Read(), active, name, verb == "rebuild")
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backend %s: %v\n", verb, err)
		return exitFor(err)
	}

	fmt.Fprintf(e.stderr, "building %s from %s\n", name, plan.Descriptor.Backend.Derive.From)
	if u := strings.TrimSpace(plan.Descriptor.Backend.Derive.IndexURL); u != "" {
		fmt.Fprintf(e.stderr, "  the build may reach %s and nothing else\n", u)
	}
	built, err := buildDerive(ctx, derive.Options{
		Descriptor: plan.Descriptor, Tag: plan.Tag, Run: runNerdctl,
		Progress: func(what string) { fmt.Fprintf(e.stderr, "  %s\n", what) },
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary backend %s: %v\n", verb, err)
		return ExitFailure
	}
	fmt.Fprintf(e.stderr, "  built %s\n", built.Digest)

	// **Exported before the ceremony, for the build's own reason.** A node can
	// neither build this image nor pull it — it is committed here and pushed
	// nowhere — so §5's "served to nodes like any other image" needs it in the
	// cache the mirror serves. A tar nothing references yet is the same
	// category as the image in the content store nothing references yet: if
	// the operator declines, neither is adopted and neither is reachable.
	cache := *distDir
	if cache == "" {
		cache = filepath.Join(paths.DataDir, api.DistDirName)
	}
	tarball := filepath.Join(cache, api.DerivedImageFile(built.Digest))
	fmt.Fprintf(e.stderr, "  exporting to the mirror\n")
	if err := derive.Export(ctx, buildRuntime, built.Digest, tarball); err != nil {
		fmt.Fprintf(e.stderr, "nodary backend %s: %v\n"+
			"  The image was built. Without the export a node cannot fetch it, so nothing\n"+
			"  is recorded — rerun once the cache is writable.\n", verb, err)
		return ExitFailure
	}

	rec, applied, code := s.attested(e, "backend "+verb, change{
		action: "backend." + verb,
		target: &audit.Target{Kind: "backend", ID: name},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The previous row is read from the transaction, so a build that
			// raced another one is refused by the intent hash rather than
			// overwriting a record of what is serving.
			prev, err := config.BuiltImage(ctx, tx, name)
			if err != nil {
				return nil, err
			}
			return config.DerivePreview(plan, prev), nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermBackendRegister); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			return config.RecordDerive(context.Background(), m, s.now, s.who.Actor.ID, plan, built)
		},
	}, cer, *format)
	if !applied {
		return code
	}

	fmt.Fprintf(e.stderr,
		"\n%s is %s. `nodary model register --backend %s` pins it into a deployment;\n"+
			"deployments already on a previous digest keep serving until they are re-registered.\n",
		name, built.Digest, name)
	reportRecord(e, rec)
	return ExitOK
}

// builtLine is how a listing says what a derive is sitting on.
func builtLine(b *backend.Built) string {
	if b == nil {
		return "not built"
	}
	if b.Stale {
		return b.Digest + " (stale: " + b.Why + ")"
	}
	return b.Digest
}

// sourceLine is the source column, which for a derive also carries the state
// §5 asks a listing to show: an image whose recipe has moved reads `stale`.
//
// A derive is always registered — a built-in is never one — so spelling it
// `derived` loses nothing and says more.
func sourceLine(b backend.Report) string {
	if b.Recipe == nil {
		return b.Source
	}
	switch {
	case b.Built == nil:
		return "derived (unbuilt)"
	case b.Built.Stale:
		return "derived (stale)"
	}
	return "derived"
}

// backendReport is what this invocation can learn about one backend, from
// whichever side it reads.
//
// The bool is "could tell", not "exists": a caller that cannot reach a registry
// falls back to what the binary carries, which is the right answer for every
// built-in and the only available one for anything else.
func backendReport(e env, rem *remote, dbPath, name string) (backend.Report, bool) {
	if rem != nil {
		var b backend.Report
		if _, err := rem.get("/backends/"+url.PathEscape(name), &b); err != nil {
			return backend.Report{}, false
		}
		return b, true
	}
	db, ok := registryDB(e, "backend", dbPath)
	if !ok {
		return backend.Report{}, false
	}
	defer db.Close()
	b, err := config.BackendReport(context.Background(), db.Read(), name)
	return b, err == nil
}
