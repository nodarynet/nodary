package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/internal/advisory"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/preflight"
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

	if *format == "json" {
		return writeJSON(e, "advisory check", map[string]any{
			"revision":  f.Revision,
			"generated": f.Generated.UTC().Format(time.RFC3339),
			"statement": f.Statement,
			"pins":      len(pins),
			"findings":  findings,
		})
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
	for _, fi := range findings {
		fix := fi.Advisory.Fixed
		if fix == "" {
			fix = "no fix published"
		}
		fmt.Fprintf(e.stdout, "%s %-16s %s (%s)\n", mark(preflight.LevelWarn),
			fi.Advisory.ID, fi.Advisory.Component, fi.Platform)
		fmt.Fprintf(e.stdout, "    pinned  %s\n", fi.Pinned)
		fmt.Fprintf(e.stdout, "    fix     %s\n", fix)
		if fi.Advisory.Summary != "" {
			fmt.Fprintf(e.stdout, "    %s\n", fi.Advisory.Summary)
		}
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
