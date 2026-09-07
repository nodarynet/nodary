package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"crypto/tls"
	"errors"
	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func cmdComponents(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary components: expected a subcommand (list, verify, fetch)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdComponentsList(e, args[1:])
	case "verify":
		return cmdComponentsVerify(e, args[1:])
	case "fetch":
		return cmdComponentsFetch(e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "nodary components: unknown subcommand %q (want list, verify or fetch)\n", args[0])
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

// cmdComponentsFetch resolves components into the cache the control plane
// serves to nodes: docs/specs/01-install.md §3 and §4's step 3.
//
// It is a verb of its own as well as a step of `server install`, because the
// cache is the thing an operator most needs to be able to repair: a node that
// cannot install has a control plane whose cache is incomplete, and re-running
// the whole install to fix one artifact is the wrong shape of remedy.
func cmdComponentsFetch(e env, args []string) int {
	fs := newFlagSet(e, "components fetch")
	format := formatFlag(fs)
	platform := fs.String("platform", "host", "platform to resolve for: host, or linux/amd64")
	dir := fs.String("dir", "", "the cache directory (default /var/lib/nodary/dist)")
	role := fs.String("role", "", "only components for this role: server or node")
	mirror := fs.Bool("mirror", false,
		"fetch through this node's control plane instead of upstream; requires an enrolled node")
	confPath := fs.String("config", "", "agent.toml path, for --mirror")
	ownership := fs.String("record", "", "where to record what was placed (default /etc/nodary/components.json)")
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
	if plat == "" {
		fmt.Fprintf(e.stderr, "nodary components fetch: --platform all is not a thing to fetch; name one\n")
		return ExitUsage
	}

	var want []components.Component
	for _, c := range m.ForPlatform(plat) {
		if *role != "" && !c.HasRole(components.Role(*role)) {
			continue
		}
		if c.Kind == components.KindImage {
			// Pulled by the container runtime from a registry by digest, which
			// is a different mechanism with different credentials.
			continue
		}
		want = append(want, c)
	}
	if len(want) == 0 {
		fmt.Fprintf(e.stderr, "nodary components fetch: nothing to fetch for %s\n", plat)
		return ExitOK
	}

	cache := *dir
	if cache == "" {
		cache = filepath.Join(paths.DataDir, "dist")
	}
	opts := components.FetchOptions{Dir: cache, Platform: plat}
	if *mirror {
		// The mirror is behind the same mTLS as the rest of the agent protocol
		// (docs/specs/01-install.md §3), so only an enrolled node can reach it
		// — which is the point: a host that has not joined has no business
		// pulling a fleet's pinned runtime.
		base, client, code := mirrorClient(e, orElse(*confPath, agent.ConfigPath()))
		if code != ExitOK {
			return code
		}
		opts.BaseURL, opts.Client = base, client
	}
	got, err := components.Fetch(context.Background(), want, opts)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components fetch: %v\n", err)
		// A digest mismatch is not a network problem and must not read like
		// one: docs/specs/01-install.md §2 has no override flag for it.
		if errors.Is(err, components.ErrDigestMismatch) {
			fmt.Fprintf(e.stderr,
				"  This is a hard stop. The bytes are not what this binary pins, and there is\n"+
					"  no flag to proceed anyway.\n")
		}
		return ExitFailure
	}

	// Recorded as fetched, not as placed: these are in nodary's own cache, and
	// `placed` means something nodary put on the host outside its own tree.
	record := *ownership
	if record == "" {
		record = filepath.Join(paths.ConfigDir, components.OwnershipFile)
	}
	owned := make([]components.Owned, 0, len(got))
	for _, f := range got {
		owned = append(owned, components.Owned{Component: f.Component, Version: f.Version,
			Path: f.Path, SHA256: f.SHA256, Placed: true})
	}
	if err := components.Record(record, versionString(), owned...); err != nil {
		// Not fatal: the artifacts are correct and verified, and an unwritable
		// record is an uninstall that has to ask rather than an install that
		// failed. Said out loud so it is not discovered at uninstall time.
		fmt.Fprintf(e.stderr, "nodary components fetch: could not record ownership in %s: %v\n",
			record, err)
	}

	if *format == "json" {
		return writeJSON(e, "components fetch", map[string]any{"fetched": got, "dir": cache})
	}
	var bytes int64
	for _, f := range got {
		fmt.Fprintf(e.stdout, "%-14s %-12s %-8s %s\n", f.Component, f.Version, f.Placement, f.Path)
		bytes += f.Bytes
	}
	fmt.Fprintf(e.stderr, "\n%d components in %s (%.1f MB)\n", len(got), cache, float64(bytes)/(1<<20))
	return ExitOK
}

// mirrorClient builds the pinned, certificate-presenting client a node uses to
// reach its control plane's cache.
//
// Everything it needs is already in agent.toml, which is why --mirror takes no
// URL: a node fetches from *its* control plane, and one it had to be told about
// separately would be one nobody pinned.
func mirrorClient(e env, confPath string) (string, *http.Client, int) {
	conf, err := agent.LoadConfig(confPath)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components fetch: %v\n", err)
		if os.IsNotExist(err) {
			fmt.Fprintf(e.stderr, "  --mirror needs an enrolled node; run `nodary node enroll` first\n")
		}
		return "", nil, exitFor(err)
	}
	pair, err := tls.LoadX509KeyPair(conf.Certificate, conf.Key)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components fetch: loading this node's certificate: %v\n", err)
		return "", nil, ExitFailure
	}
	client, err := agent.Client(conf.CAFingerprint, &pair)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary components fetch: %v\n", err)
		return "", nil, ExitFailure
	}
	// Longer than the agent's own 90-second budget: a component is tens of
	// megabytes and a long-poll is a few hundred bytes.
	client.Timeout = 30 * time.Minute
	return strings.TrimRight(conf.Server, "/") + api.Prefix + "/agent/dist", client, ExitOK
}
