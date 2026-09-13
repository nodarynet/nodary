package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/preflight"
)

// `nodary upgrade` converges this host onto the release whose binary is running.
//
// [01 §9](../../docs/specs/01-install.md#9-upgrade) splits an upgrade in two:
// replace the binary, then move everything the new release pins. install.sh is
// already the first half — it downloads a release, verifies its signature and
// its digest, and unpacks it beside the old one. Nothing did the second half,
// and that is where a CVE response actually lands: the LiteLLM image a control
// plane runs is written into /etc/nodary/litellm.env once, at install time,
// from the manifest embedded in the binary of the day. A release that moves
// that pin leaves the file alone, so the fixed digest sits in the new binary's
// manifest and the vulnerable image keeps starting.
//
// Re-running `server install` is not the answer: it rewrites server.toml from
// its own flag defaults, so an upgrade that way silently resets the bind
// address and drops the --host names the operator gave the first time. This
// verb touches only what the release decides and nothing the operator did.

// move is one pinned thing this release changes on this host.
type move struct {
	What string `json:"what"`
	From string `json:"from"`
	To   string `json:"to"`
}

func cmdUpgrade(e env, args []string) int {
	fs := newFlagSet(e, "upgrade")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	check := fs.Bool("check", false, "report which pins would move, and change nothing")
	to := fs.String("to", "", "not implemented; this upgrades to the release already installed")
	root := fs.String("root", "", "operate under this prefix instead of / (for testing; nothing is restarted)")
	svcUser := fs.String("user", "nodary", "the service account; empty runs as root")
	offline := fs.Bool("offline", false,
		"do not contact any upstream source; the mirror is whatever is already in the data directory")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if *to != "" {
		// Refused by name rather than quietly absent. Fetching a release means
		// verifying a release signature, and install.sh's NODARY_PUBKEY is
		// still REPLACE_AT_RELEASE_TIME — there is no key to check against, so
		// a download here would be an unverified one, which 01 §2 has no flag
		// for.
		fmt.Fprintf(e.stderr, "nodary upgrade: --to is not implemented.\n"+
			"  This converges the host onto the release it is running (%s). Fetch and\n"+
			"  verify the one you want first, then run it:\n"+
			"    curl -fsSL https://nodary.net/install.sh | sh\n"+
			"    sudo nodary upgrade\n", versionString())
		return ExitUsage
	}

	confDir := filepath.Join(*root, paths.ConfigDir)
	optDir := filepath.Join(*root, paths.OptDir)
	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}
	plat := resolvePlatform("host")
	moves, err := plannedMoves(m, confDir, optDir, plat)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
		return ExitFailure
	}

	if *check {
		return reportMoves(e, *format, moves)
	}

	// A GPU node has no database to attest into and no LiteLLM to repin, and
	// its half of §9 is an agent that upgrades itself from the control plane's
	// mirror — R5-16, which is not built. Saying so is better than opening a
	// control-plane database here, which store.Open would happily create.
	if path, _ := resolveDB(*dbPath); !fileExists(path) && fileExists(agent.ConfigPath()) {
		fmt.Fprintf(e.stderr, "nodary upgrade: this host is a GPU node, not a control plane.\n"+
			"  Agents upgrade from their control plane's mirror (R5-16), which is not built\n"+
			"  in this release. Until it is, re-run install.sh on this host.\n")
		return ExitFailure
	}

	s, ok := openSession(e, "upgrade", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	rec, applied, code := s.attested(e, "upgrade", change{
		action: "host.upgrade",
		target: &audit.Target{Kind: "host", ID: buildinfo.Version},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// Re-read rather than closing over the moves computed above: the
			// render runs twice by contract, and the second run is what binds
			// the approved preview to what is applied.
			moves, err := plannedMoves(m, confDir, optDir, plat)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"version": buildinfo.Version,
				"from":    installedRelease(optDir),
				"moves":   moves,
			}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			m.Detail("from", installedRelease(optDir))
			m.Detail("to", buildinfo.Version)
			return nil
		},
	}, cer, *format)
	if !applied {
		return code
	}

	if code := applyUpgrade(e, s, m, moves, confDir, plat, *offline,
		install.Options{Root: *root, User: *svcUser}); code != ExitOK {
		return code
	}
	reportRecord(e, rec)
	return ExitOK
}

// applyUpgrade moves everything the release decides, in the order 01 §9 names:
// the backup first, then the binary, then what runs against it.
func applyUpgrade(e env, s *session, m *components.Manifest, moves []move,
	confDir, plat string, offline bool, o install.Options) int {
	ctx := context.Background()

	// The backup before anything moves. An upgrade nobody can undo is not one
	// anybody should run on a Friday, and the destination is under the data
	// directory because that is already 0700 — `backup create` refuses to write
	// anywhere other users can read, and so should this.
	dataDir := filepath.Dir(s.db.Path())
	dir := filepath.Join(dataDir, "backup")
	if err := os.MkdirAll(dir, paths.ModeDataDir); err != nil {
		fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
		return ExitFailure
	}
	out := filepath.Join(dir, fmt.Sprintf("pre-upgrade-%s-%s.tar.gz",
		buildinfo.Version, s.now.UTC().Format("20060102T150405Z")))
	if err := writeBackup(e, s, out, confDir); err != nil {
		os.Remove(out)
		fmt.Fprintf(e.stderr, "nodary upgrade: taking the pre-upgrade backup: %v\n", err)
		return ExitFailure
	}
	report(e, []install.Step{{Name: "backup", Changed: true, Detail: out}})

	// The binary, then the units that invoke it. EnsureBinary places the
	// running executable under its own version and flips `current`, which is
	// what every unit's ExecStart follows.
	steps, _, err := install.EnsureBinary(buildinfo.Version, o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
		return ExitFailure
	}
	report(e, steps)

	// Both roles when the host serves both: a --with-node box runs the agent's
	// units too, and an upgrade that moved the binary under half of them would
	// leave the other half invoking a version that no longer exists.
	roles := []string{"server"}
	if fileExists(filepath.Join(o.Root, agent.ConfigPath())) {
		roles = append(roles, "node")
	}
	restart := map[string]bool{}
	ours := map[string]bool{}
	for _, role := range roles {
		for name := range install.Units(role) {
			ours[name] = true
		}
		units, err := install.WriteUnits(ctx, role, o)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
			return ExitFailure
		}
		report(e, units)
		for _, st := range units {
			if name, ok := strings.CutPrefix(st.Name, "unit: "); ok && st.Changed {
				restart[name] = true
			}
		}
	}

	// The node runtime this control plane serves to its fleet, and the copies
	// of it this host runs itself. --offline for the same reason `server
	// install` has one: an air-gapped site's mirror is filled from a bundle,
	// and reaching for a CDN there fails slowly rather than not at all.
	fetched := []components.Fetched(nil)
	if offline {
		report(e, []install.Step{{Name: "components",
			Detail: "skipped by --offline; the mirror is whatever is already in " + dataDir}})
	} else {
		fetched = fetchIntoMirror(e, ctx, "upgrade", dataDir)
	}
	if len(fetched) > 0 {
		record := filepath.Join(confDir, components.OwnershipFile)
		placed, err := install.PlaceComponents(ctx, fetched, o, record, versionString())
		if err != nil {
			fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "runtime", err)
		} else {
			report(e, placed)
		}
	}

	// The data plane's pin. The whole reason this verb exists.
	if image, err := imageFor(m, "litellm", plat); err == nil {
		step, err := writeLiteLLMImage(confDir, image)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
			return ExitFailure
		}
		report(e, []install.Step{step})
		if step.Changed {
			restart["nodary-litellm.service"] = true
		}
	}

	owned, err := install.EnsureOwnership(o)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary upgrade: %v\n", err)
		return ExitFailure
	}
	report(e, owned)

	// A new binary means every nodary unit is running the old one until it is
	// told otherwise. containerd is upstream's and is left alone: bouncing it
	// stops every container on the host, which is a far larger act than the
	// archive digest that moved under it.
	for _, w := range moves {
		if w.What != "nodary" {
			continue
		}
		for _, u := range []string{"nodary-server.service", "nodary-gateway.service", "nodary-agent.service"} {
			// Only what this host has a unit for: a control plane with no agent
			// has no nodary-agent.service, and asking systemd to restart one
			// would report a failure for something never installed.
			if ours[u] {
				restart[u] = true
			}
		}
	}
	return restartUnits(e, ctx, restart, o)
}

// restartUnits bounces what moved, data plane before the API that proxies to
// it, in the same dependency order an install starts them.
func restartUnits(e env, ctx context.Context, want map[string]bool, o install.Options) int {
	order := []string{"nodary-litellm.service", "nodary-server.service",
		"nodary-gateway.service", "nodary-agent.service"}
	for _, u := range order {
		if !want[u] {
			continue
		}
		step, err := install.Restart(ctx, u, o)
		if err != nil {
			// Reported, not fatal. The files are already correct; what is left
			// is one systemctl the operator can run, and unwinding the rest
			// would put the host back on the release they asked to leave.
			fmt.Fprintf(e.stdout, "%s %-18s %v\n", mark(preflight.LevelWarn), "restart", err)
			continue
		}
		report(e, []install.Step{step})
	}
	return ExitOK
}

// plannedMoves compares what this binary pins against what the host is running.
//
// Only pins: the release, the container image written into an environment file,
// and the digest of every archive and binary in the ownership record. Unit
// bodies are deliberately not here — they are rewritten unconditionally and
// WriteUnits already reports which ones changed, so listing them would be a
// second and worse answer to a question something else already answers.
func plannedMoves(m *components.Manifest, confDir, optDir, plat string) ([]move, error) {
	var out []move
	if was := installedRelease(optDir); was != buildinfo.Version {
		out = append(out, move{"nodary", orElse(was, "not installed"), buildinfo.Version})
	}
	if image, err := imageFor(m, "litellm", plat); err == nil {
		// A read that failed for any reason other than absence is not a pin
		// that moved. Swallowing it would report an upgrade as available, or a
		// host as current, on the strength of a file nobody could open —
		// which is the one answer this verb must never guess at.
		body, err := os.ReadFile(filepath.Join(confDir, "litellm.env"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if was := trimEnvValue(string(body), "NODARY_LITELLM_IMAGE"); was != image {
			out = append(out, move{"litellm", orElse(was, "not pinned"), image})
		}
	}

	// Against the ownership record rather than the manifest alone: a component
	// this host never placed is not one an upgrade moves, and R5-11's rule is
	// that ownership is recorded and never inferred.
	record, err := components.LoadOwnership(filepath.Join(confDir, components.OwnershipFile))
	if err != nil {
		return nil, err
	}
	have := make(map[string]components.Owned, len(record.Components))
	for _, o := range record.Components {
		have[o.Component] = o
	}
	for _, c := range m.ForPlatform(plat) {
		a := c.Platforms[plat]
		if a.SHA256 == "" {
			// An image: pulled by digest by the container runtime at unit
			// start, so its move is the environment file above, not a file
			// anything on this host holds.
			continue
		}
		o, ok := have[c.Name]
		if !ok || o.SHA256 == a.SHA256 {
			continue
		}
		out = append(out, move{c.Name,
			o.Version + " " + shortDigest(o.SHA256), c.Version + " " + shortDigest(a.SHA256)})
	}
	return out, nil
}

// installedRelease is the version `current` points at, which is the binary
// every unit actually invokes. Empty when nothing is installed under /opt.
func installedRelease(optDir string) string {
	target, err := os.Readlink(filepath.Join(optDir, "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimRight(target, string(os.PathSeparator)))
}

func shortDigest(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func reportMoves(e env, format string, moves []move) int {
	if format == "json" {
		return writeJSON(e, "upgrade", map[string]any{
			"version": buildinfo.Version, "moves": moves})
	}
	if len(moves) == 0 {
		fmt.Fprintf(e.stdout, "nothing to move: this host is at %s\n", versionString())
		return ExitOK
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "WHAT\tFROM\tTO\n")
	for _, w := range moves {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", w.What, w.From, w.To)
	}
	if code := flush(e, "upgrade", tw); code != ExitOK {
		return code
	}
	fmt.Fprintf(e.stderr, "\n%d pin(s) would move. `sudo nodary upgrade` applies them, "+
		"after taking a backup.\n", len(moves))
	return ExitOK
}
