package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
)

func cmdComponents(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary components: expected a subcommand (list, verify)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdComponentsList(e, args[1:])
	case "verify":
		return cmdComponentsVerify(e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "nodary components: unknown subcommand %q (want list or verify)\n", args[0])
		return ExitUsage
	}
}

// loadManifest reads the embedded manifest and refuses to proceed if it is
// structurally invalid. A malformed manifest is a build defect, so it is worth
// failing loudly rather than acting on half of it.
func loadManifest(e env) (*components.Manifest, bool) {
	m, err := components.Load()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components: %v\n", err)
		return nil, false
	}
	if errs := m.Validate(); len(errs) > 0 {
		fmt.Fprintf(e.stderr, "nodary components: embedded manifest is invalid\n")
		for _, err := range errs {
			fmt.Fprintf(e.stderr, "  %v\n", err)
		}
		return nil, false
	}
	return m, true
}

// resolvePlatform maps the --platform flag onto a manifest key. Empty means
// every platform.
func resolvePlatform(spec string) string {
	switch spec {
	case "", "host":
		return buildinfo.Platform()
	case "all":
		return ""
	default:
		return spec
	}
}

func cmdComponentsList(e env, args []string) int {
	fs := newFlagSet(e, "components list")
	format := formatFlag(fs)
	platform := fs.String("platform", "host", "platform key, or 'all' (default: this host)")
	long := fs.Bool("long", false, "include the full artifact URL and digest")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}
	plat := resolvePlatform(*platform)

	var selected []components.Component
	if plat == "" {
		selected = append(selected, m.Components...)
		sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })
	} else {
		selected = m.ForPlatform(plat)
		if len(selected) == 0 {
			fmt.Fprintf(e.stderr, "nodary components list: no components for platform %q\n", plat)
			return ExitFailure
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		out := struct {
			NodaryVersion string                 `json:"nodary_version"`
			Platform      string                 `json:"platform,omitempty"`
			Components    []components.Component `json:"components"`
		}{m.NodaryVersion, plat, selected}
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(e.stderr, "nodary components list: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "COMPONENT\tVERSION\tKIND\tGROUP\tROLES\tSOURCE")
	for _, c := range selected {
		roles := make([]string, 0, len(c.Roles))
		for _, r := range c.Roles {
			roles = append(roles, string(r))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Version, c.Kind, c.Group, strings.Join(roles, ","), sourceOf(c, plat))
	}
	tw.Flush()

	if *long {
		fmt.Fprintln(e.stdout)
		for _, c := range selected {
			fmt.Fprintf(e.stdout, "%s %s\n", c.Name, c.Version)
			if c.Notes != "" {
				fmt.Fprintf(e.stdout, "  %s\n", c.Notes)
			}
			for _, p := range sortedKeys(c.Platforms) {
				if plat != "" && p != plat {
					continue
				}
				a := c.Platforms[p]
				if c.Kind == components.KindImage {
					fmt.Fprintf(e.stdout, "  %-14s %s\n", p, a.Image)
					continue
				}
				fmt.Fprintf(e.stdout, "  %-14s %s\n", p, a.URL)
				fmt.Fprintf(e.stdout, "  %-14s sha256:%s\n", "", a.SHA256)
			}
		}
	}
	return ExitOK
}

// sourceOf renders a short, honest origin for the table: the host an artifact
// comes from, which is the thing an operator reviewing a manifest cares about.
func sourceOf(c components.Component, plat string) string {
	pick := plat
	if pick == "" {
		pick = sortedKeys(c.Platforms)[0]
	}
	a, ok := c.Platforms[pick]
	if !ok {
		return "-"
	}
	if c.Kind == components.KindImage {
		ref := a.Image
		if i := strings.Index(ref, "@"); i >= 0 {
			ref = ref[:i]
		}
		return ref
	}
	u, err := url.Parse(a.URL)
	if err != nil {
		return a.URL
	}
	return u.Host
}

func sortedKeys(m map[string]components.Artifact) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cmdComponentsVerify(e env, args []string) int {
	fs := newFlagSet(e, "components verify")
	format := formatFlag(fs)
	platform := fs.String("platform", "all", "platform key, 'host', or 'all'")
	offline := fs.Bool("offline", false, "structural validation only; no network")
	full := fs.Bool("full", false, "download every artifact and hash it (slow)")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}

	results := m.Verify(context.Background(), components.VerifyOptions{
		Platform: resolvePlatform(*platform),
		Offline:  *offline,
		Full:     *full,
	})
	sort.Slice(results, func(i, j int) bool {
		if results[i].Component != results[j].Component {
			return results[i].Component < results[j].Component
		}
		return results[i].Platform < results[j].Platform
	})

	failed := 0
	for _, r := range results {
		if !r.OK() {
			failed++
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		out := struct {
			NodaryVersion string              `json:"nodary_version"`
			Checked       int                 `json:"checked"`
			Failed        int                 `json:"failed"`
			Results       []components.Result `json:"results"`
		}{m.NodaryVersion, len(results), failed, results}
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(e.stderr, "nodary components verify: %v\n", err)
			return ExitFailure
		}
		if failed > 0 {
			return ExitFailure
		}
		return ExitOK
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	for _, r := range results {
		mark := "✔"
		if !r.OK() {
			mark = "✘"
		} else if r.Status == components.StatusSkipped {
			mark = "–"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, r.Component, r.Platform, r.Status, r.Detail)
	}
	tw.Flush()

	// The summary is a diagnostic, not the result, so it goes to stderr and
	// leaves stdout parseable.
	fmt.Fprintf(e.stderr, "\n%d checked, %d failed\n", len(results), failed)
	if failed > 0 {
		return ExitFailure
	}
	return ExitOK
}
