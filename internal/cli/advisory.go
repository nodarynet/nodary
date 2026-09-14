package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/internal/advisory"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/preflight"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdAdvisory(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary advisory: expected a subcommand (check)\n")
		return ExitUsage
	}
	if args[0] != "check" {
		fmt.Fprintf(e.stderr, "nodary advisory: unknown subcommand %q (want check)\n", args[0])
		return ExitUsage
	}
	return cmdAdvisoryCheck(e, args[1:])
}

// FeedPath is where a revision is installed. Beside the other configuration,
// with its signature next to it, the way a license arrives.
func feedPath() string { return filepath.Join(paths.ConfigDir, "advisories.toml") }

// cmdAdvisoryCheck is R9-15: feed revisions matched against pinned digests.
//
// It reports and changes nothing. R9-16 turns an undecided advisory into a
// POA&M item with a clock and R9-17 records the decision, and both are
// mutations through the audit chain — this verb is the read that precedes them,
// and keeping it read-only is what lets an operator run it on a whim.
func cmdAdvisoryCheck(e env, args []string) int {
	fs := newFlagSet(e, "advisory check")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	feed := fs.String("feed", "", "revision to check against (default "+feedPath()+")")
	sigPath := fs.String("signature", "", "detached signature (default: the feed path plus .minisig)")
	platform := fs.String("platform", "host", "which pins to check: host, linux/amd64, or all")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path := orElse(*feed, feedPath())
	src, err := os.ReadFile(path)
	if err != nil {
		// Named, not guessed at. A site with no subscription has no feed, and
		// that is a different thing from a feed that says nothing — which is
		// exactly the distinction R9-15 asks for.
		if os.IsNotExist(err) {
			fmt.Fprintf(e.stderr, "nodary advisory check: no feed at %s.\n"+
				"  A revision is signed content; `nodary advisory check --feed FILE` reads one from elsewhere.\n", path)
			return ExitFailure
		}
		fmt.Fprintf(e.stderr, "nodary advisory check: %v\n", err)
		return ExitFailure
	}
	sig, err := os.ReadFile(orElse(*sigPath, path+".minisig"))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary advisory check: %v\n", err)
		fmt.Fprintf(e.stderr, "  a revision is only worth reading if it verifies; there is no unsigned mode\n")
		return ExitFailure
	}

	f, err := advisory.Parse(string(src), string(sig))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary advisory check: %v\n", err)
		return exitFor(err)
	}

	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}
	pins := pinnedDigests(m, resolvePlatform(*platform))
	findings := f.Match(pins)

	// R9-16's clock. Recorded rather than derived from the revision's
	// `generated` stamp, and the note below says what an absent control plane
	// costs, because a report with no clock and a report with a clock that
	// found nothing overdue look identical otherwise.
	known, interval, clock := recordFindings(e, *dbPath, f.Revision, findings)
	now := time.Now()

	if *format == "json" {
		out := map[string]any{
			"revision":  f.Revision,
			"generated": f.Generated.UTC().Format(time.RFC3339),
			"statement": f.Statement,
			"pins":      len(pins),
			"findings":  findings,
		}
		if clock {
			out["decision_interval_days"] = interval
			out["known"] = knownJSON(known, now, interval)
		}
		return writeJSON(e, "advisory check", out)
	}

	fmt.Fprintf(e.stdout, "revision %d, generated %s (%s ago)\n",
		f.Revision, f.Generated.UTC().Format(time.RFC3339), roundDuration(f.Age(time.Now())))
	fmt.Fprintf(e.stdout, "checked %d pinned digest(s)\n\n", len(pins))

	if len(findings) == 0 {
		// An honest empty result, and it says what was checked rather than just
		// "ok" — "nothing found" and "nothing looked at" read identically
		// otherwise, and only one of them is good news.
		fmt.Fprintf(e.stdout, "%s no advisory in this revision applies to a digest this build pins\n",
			mark(preflight.LevelOK))
	}
	// Indexed by the finding's identity so the clock can be printed beside the
	// advisory it belongs to, without the reporting loop caring whether there
	// is a control plane underneath it.
	since := map[string]advisory.Known{}
	for _, k := range known {
		since[k.Advisory.ID+"\x00"+k.Platform] = k
	}
	var overdue int
	for _, fi := range findings {
		fix := fi.Advisory.Fixed
		if fix == "" {
			fix = "no fix published"
		}
		level := preflight.LevelWarn
		k, tracked := since[fi.Advisory.ID+"\x00"+fi.Platform]
		if tracked && k.POAM(now, interval) {
			// A POA&M item is not a worse vulnerability than the one beside
			// it; it is the same one with nobody's name against it.
			level = preflight.LevelFail
			overdue++
		}
		fmt.Fprintf(e.stdout, "%s %-16s %s (%s)\n", mark(level),
			fi.Advisory.ID, fi.Advisory.Component, fi.Platform)
		fmt.Fprintf(e.stdout, "    pinned  %s\n", fi.Pinned)
		fmt.Fprintf(e.stdout, "    fix     %s\n", fix)
		if tracked {
			detail := fmt.Sprintf("known %d day(s), since revision %d",
				k.Days(now), k.FeedRevision)
			if k.POAM(now, interval) {
				detail += fmt.Sprintf(" — no decision after %d; this is a POA&M item", interval)
			}
			fmt.Fprintf(e.stdout, "    clock   %s\n", detail)
		}
		if fi.Advisory.Summary != "" {
			fmt.Fprintf(e.stdout, "    %s\n", fi.Advisory.Summary)
		}
	}

	if !clock && len(findings) > 0 {
		fmt.Fprintf(e.stderr, "\nNo control plane here, so nothing is tracking how long these have\n"+
			"been known; run this on the control-plane host for the decision clock.\n")
	}
	if overdue > 0 {
		fmt.Fprintf(e.stderr, "\n%d finding(s) have gone %d day(s) with no decision recorded.\n"+
			"  A decision is patch, defer with justification, or accept with a compensating\n"+
			"  control — all three close the clock; none of them is doing nothing.\n",
			overdue, interval)
	}

	fmt.Fprintf(e.stderr, "\n%s\n", f.Statement)
	return ExitOK
}

// pinnedDigests is every digest this build would place, which is what an
// advisory is matched against.
//
// Every platform when `plat` is empty (`--platform all`): a control plane
// mirrors artifacts for the architectures its nodes run, not only its own, and
// an advisory against the arm64 tarball is one an amd64 control plane still
// needs to know about because it is serving it.
func pinnedDigests(m *components.Manifest, plat string) []advisory.Pin {
	var pins []advisory.Pin
	for _, c := range m.Components {
		for p, art := range c.Platforms {
			if plat != "" && p != plat {
				continue
			}
			if art.SHA256 == "" {
				// An image is pinned by its registry digest elsewhere; a
				// component with no digest here is one this check cannot speak
				// to, and silently counting it would overstate the coverage.
				continue
			}
			pins = append(pins, advisory.Pin{Component: c.Name, Platform: p, SHA256: art.SHA256})
		}
	}
	return pins
}

// roundDuration prints an age a person reads rather than 723h41m12.4s.
func roundDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return d.Round(time.Minute).String()
	case d < 48*time.Hour:
		return d.Round(time.Hour).String()
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// recordFindings notes what this install now knows, and reads back since when.
//
// A control plane is where that record lives, so a check run anywhere else
// reports the findings and no clock — and says so, because a report with no
// clock and a report whose clock found nothing look identical otherwise. It is
// a plain write rather than a mutation: nobody decided anything by looking.
func recordFindings(e env, dbPath string, revision int, findings []advisory.Finding) (
	[]advisory.Known, int, bool) {

	if len(findings) == 0 {
		return nil, 0, false
	}
	ctx := context.Background()
	path, _ := resolveDB(dbPath)
	db, err := store.Open(ctx, path)
	if err != nil {
		return nil, 0, false
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return nil, 0, false
	}
	active, _, err := policy.Active(ctx, db.Read())
	if err != nil {
		return nil, 0, false
	}
	known, err := advisory.Record(ctx, db, time.Now(), revision, findings)
	if err != nil {
		// Reported, not fatal: the findings themselves are the answer, and a
		// check that refused to print them because a clock could not be
		// written would withhold the useful half.
		fmt.Fprintf(e.stderr, "nodary advisory check: %v\n", err)
		return nil, 0, false
	}
	return known, active.AdvisoryDecisionDays, true
}

func knownJSON(known []advisory.Known, now time.Time, interval int) []map[string]any {
	out := make([]map[string]any, 0, len(known))
	for _, k := range known {
		out = append(out, map[string]any{
			"advisory_id":   k.Advisory.ID,
			"platform":      k.Platform,
			"first_seen":    k.FirstSeen.UTC().Format(time.RFC3339),
			"feed_revision": k.FeedRevision,
			"days_known":    k.Days(now),
			"poam":          k.POAM(now, interval),
		})
	}
	return out
}
