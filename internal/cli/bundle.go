package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/backup"
	"github.com/nodarynet/nodary/internal/bundle"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/paths"
)

// runNerdctl is how this verb reaches the container runtime.
//
// Named and in one place because it is the only thing in the offline path that
// is not pure file handling: an operator whose connected machine has no
// containerd gets a clear failure from here rather than a confusing one from
// inside an export.
func runNerdctl(ctx context.Context, name string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, fmt.Errorf("%s is not on PATH, and container images cannot be exported or "+
			"loaded without it", name)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// cmdBundle is docs/specs/01-install.md §6, the offline install.
//
// `create` on a connected machine, `open` on the air-gapped one, and `show` for
// the question an operator actually asks about a forty-gigabyte file somebody
// handed them: what is in this.
func cmdBundle(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary bundle: expected a subcommand (create, show, open)\n")
		return ExitUsage
	}
	switch args[0] {
	case "create":
		return cmdBundleCreate(e, args[1:])
	case "show":
		return cmdBundleShow(e, args[1:])
	case "open":
		return cmdBundleOpen(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary bundle: unknown subcommand %q (want create, show or open)\n", args[0])
	return ExitUsage
}

// cmdBundleCreate assembles a bundle from the cache.
//
// **It does not download.** `components fetch` already does exactly that and
// verifies every digest before a file lands, so this reads the cache that verb
// fills. A downloader here would be a second place the verification could
// differ, which is the whole failure §6's "both verify identically" is about —
// and it would also mean an operator could not see, separately, whether their
// cache was sound before committing to a multi-gigabyte archive.
func cmdBundleCreate(e env, args []string) int {
	fs := newFlagSet(e, "bundle create")
	format := formatFlag(fs)
	platform := fs.String("platform", "host", "platform to resolve for: host, or linux/amd64")
	comps := fs.String("components", "all",
		"component groups to carry: all, minimal, none, or a list")
	backends := fs.String("backends", "", "backend images to carry: all, or a list; none by default")
	role := fs.String("role", "", "only components for this role: server or node")
	dir := fs.String("dir", "", "the cache to read (default /var/lib/nodary/dist)")
	feed := fs.String("feed", "", "advisory feed revision to carry (default "+feedPath()+
		" when it exists; \"none\" to omit)")
	out := fs.String("o", "", "write the bundle here")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if *out == "" {
		fmt.Fprintf(e.stderr, "nodary bundle create: -o FILE is required\n")
		return ExitUsage
	}
	plat := resolvePlatform(*platform)
	if plat == "" {
		fmt.Fprintf(e.stderr, "nodary bundle create: --platform all is not a thing to bundle; name one\n")
		return ExitUsage
	}
	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}

	// Both roles by default: a bundle carries a site, and a site has a control
	// plane and nodes. Narrowing it is the flag.
	var wanted []components.Component
	roles := []components.Role{components.RoleServer, components.RoleNode}
	if *role != "" {
		roles = []components.Role{components.Role(*role)}
	}
	// **A name is resolved against the union of the roles, not against each
	// one.** `cni-plugins` is a node component, so asking the server role for
	// it answers "unknown component" — which is true of that role and false of
	// the site, and a bundle is for a site. So a miss is only a miss when
	// every role missed.
	seen := map[string]bool{}
	var missed error
	matched := *comps == "none"
	for _, r := range roles {
		if matched {
			break
		}
		got, err := m.Select(r, *comps)
		if err != nil {
			missed = err
			continue
		}
		matched = true
		for _, c := range got {
			if _, has := c.Platforms[plat]; !has || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			wanted = append(wanted, c)
		}
	}
	if !matched && missed != nil {
		fmt.Fprintf(e.stderr, "nodary bundle create: %v\n", missed)
		return ExitUsage
	}
	carried, code := feedToCarry(e, *feed)
	if code >= 0 {
		return code
	}
	chosen, err := m.SelectBackends(*backends)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle create: %v\n", err)
		return ExitUsage
	}

	// Images travel as exports and everything else as the file the cache
	// already holds, so the two are separated here rather than inside the
	// bundle package: which is which is a property of the manifest.
	var archives, images []components.Component
	for _, c := range append(append([]components.Component{}, wanted...), chosen...) {
		if c.Kind == components.KindImage {
			images = append(images, c)
			continue
		}
		archives = append(archives, c)
	}
	// A bundle carrying only a feed revision is the *recurring* case, not a
	// degenerate one: an offline site installs the gigabytes once and then
	// receives R9-18's revisions monthly, and making it re-carry every image
	// to do so would mean it simply would not. `--components none` is how.
	if len(archives) == 0 && len(images) == 0 && len(carried) == 0 {
		fmt.Fprintf(e.stderr, "nodary bundle create: nothing selected for %s; name components, "+
			"backends, or a feed to carry\n", plat)
		return ExitUsage
	}

	cache := *dir
	if cache == "" {
		cache = filepath.Join(paths.DataDir, "dist")
	}
	if *format != "json" {
		fmt.Fprintf(e.stderr, "Building %s for %s\n", *out, plat)
	}
	var run bundle.Runner
	if len(images) > 0 {
		run = runNerdctl
	}
	res, err := bundle.Create(context.Background(), bundle.CreateOptions{
		Out: *out, Platform: plat, Dist: cache,
		Components: archives, Images: images, Config: carried,
		ManifestDoc:   components.Document(),
		NodaryVersion: versionString(),
		Run:           run,
		Progress: func(what string) {
			if *format != "json" {
				fmt.Fprintf(e.stderr, "  %s\n", what)
			}
		},
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle create: %v\n", err)
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "bundle create", res)
	}
	printBundle(e, res)
	fmt.Fprintf(e.stderr,
		"\nWrote %s. On the air-gapped host:\n"+
			"  sh install.sh server --offline --bundle %s\n", *out, filepath.Base(*out))
	return ExitOK
}

func cmdBundleShow(e env, args []string) int {
	fs := newFlagSet(e, "bundle show")
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary bundle show: expected one bundle path\n")
		return ExitUsage
	}
	m, err := bundle.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle show: %v\n", err)
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "bundle show", m)
	}
	printBundle(e, m)
	return ExitOK
}

// cmdBundleOpen extracts a bundle into the cache, verifying as it goes.
//
// The verbs are separate because the acts are: opening a bundle warms a cache
// and loads images, and installing is what `server install` then does against
// a cache it finds already full. An operator who wants to check media before
// committing to an install runs this on its own.
func cmdBundleOpen(e env, args []string) int {
	fs := newFlagSet(e, "bundle open")
	format := formatFlag(fs)
	dir := fs.String("dir", "", "the cache to fill (default /var/lib/nodary/dist)")
	noImages := fs.Bool("no-images", false,
		"verify the images but do not load them into the container runtime")
	confDir := fs.String("config-dir", "",
		"where carried configuration lands (default "+paths.ConfigDir+")")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary bundle open: expected one bundle path\n")
		return ExitUsage
	}
	m, ok := loadManifest(e)
	if !ok {
		return ExitFailure
	}
	cache := *dir
	if cache == "" {
		cache = filepath.Join(paths.DataDir, "dist")
	}

	head, err := bundle.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle open: %v\n", err)
		return ExitFailure
	}
	var run bundle.Runner
	if !*noImages && len(head.Images) > 0 {
		run = runNerdctl
	}
	_, got, err := bundle.Open(context.Background(), fs.Arg(0), bundle.OpenOptions{
		Dist: cache, Pinned: m, Platform: head.Platform, Run: run,
		Config: orElse(*confDir, paths.ConfigDir),
		Progress: func(what string) {
			if *format != "json" {
				fmt.Fprintf(e.stderr, "  %s\n", what)
			}
		},
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle open: %v\n", err)
		// A digest mismatch is not a transfer problem and must not read like
		// one. §2 has no override flag for it and neither does this.
		if errors.Is(err, bundle.ErrDigestMismatch) {
			fmt.Fprintf(e.stderr,
				"  This is a hard stop. The bytes are not what this binary pins, and there is\n"+
					"  no flag to proceed anyway.\n")
		}
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "bundle open", map[string]any{"opened": got, "dir": cache})
	}
	for _, o := range got {
		what := "cached"
		switch {
		case o.Loaded:
			what = "loaded"
		case o.Config:
			what = "placed"
		}
		fmt.Fprintf(e.stdout, "%-14s %-8s %s\n", o.Name, what, o.Path)
	}
	fmt.Fprintf(e.stderr, "\n%d members verified into %s.\n", len(got), cache)
	if run == nil && len(head.Images) > 0 {
		fmt.Fprintf(e.stderr,
			"Images were verified and not loaded; drop --no-images to hand them to the runtime.\n")
	}
	return ExitOK
}

func printBundle(e env, m bundle.Manifest) {
	fmt.Fprintf(e.stdout, "nodary %s, %s, built %s\n", m.NodaryVersion, m.Platform, m.CreatedAt)
	for _, c := range m.Components {
		fmt.Fprintf(e.stdout, "  %-14s %-12s %9s  %s\n", c.Component, c.Version,
			backup.HumanBytes(c.Bytes), c.SHA256[:12])
	}
	for _, i := range m.Images {
		fmt.Fprintf(e.stdout, "  %-14s %-12s %9s  image\n", i.Component, i.Version,
			backup.HumanBytes(i.Bytes))
	}
	for _, c := range m.Config {
		fmt.Fprintf(e.stdout, "  %-14s %-12s %9s  %s\n", c.Component, "config",
			backup.HumanBytes(c.Bytes), c.SHA256[:12])
	}
	fmt.Fprintf(e.stdout, "  %d members, %s\n",
		len(m.Components)+len(m.Images)+len(m.Config), backup.HumanBytes(m.Bytes()))
}

// offlineTransport is what `--offline` gives the fetcher instead of a network.
//
// An artifact the bundle did not carry is a gap in the bundle, and that is
// what it has to say. Left to a real client it would surface on an air-gapped
// host as a DNS failure or a hung connect — a symptom that names the network
// rather than the thing actually missing, on the one machine where the network
// was never going to answer.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%s is not in the bundle and this install is offline, so there is "+
		"nowhere to fetch it from; rebuild the bundle with --components all",
		path.Base(r.URL.Path))
}

// feedToCarry is R9-18: an air-gapped site's only route to a feed revision.
//
// The bundle carries the revision and its detached signature and checks
// neither. `advisory check` verifies the signature on every read, with no way
// to skip it, and that verification is the one that means something — a second
// one here would either duplicate it or, worse, look like the one that
// counted. What this does check is that the signature is *present*, because a
// revision that arrives without one is unreadable at the far end and the whole
// point of the exercise is not to discover that on the air-gapped machine.
func feedToCarry(e env, flag string) ([]string, int) {
	if flag == "none" {
		return nil, -1
	}
	path := orElse(flag, feedPath())
	if _, err := os.Stat(path); err != nil {
		// Named only when it was asked for. A site with no subscription has no
		// feed, and a bundle without one is ordinary rather than broken.
		if flag == "" {
			return nil, -1
		}
		fmt.Fprintf(e.stderr, "nodary bundle create: %v\n", err)
		return nil, ExitFailure
	}
	sig := path + ".minisig"
	if _, err := os.Stat(sig); err != nil {
		fmt.Fprintf(e.stderr, "nodary bundle create: %s has no signature at %s, and an unsigned\n"+
			"  revision is one the receiving site will refuse to read\n", path, sig)
		return nil, ExitFailure
	}
	return []string{path, sig}, -1
}
