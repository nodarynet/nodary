package derive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/backend"
)

// Gateway is the address a container on `nodary-isolated` reaches the host at.
//
// It is the bridge's own address, and the container can reach it **by design
// rather than by accident**: internal/agent/network.go sets `isGateway: true`
// so that portmap's DNAT has a route back, and records that the container can
// address the host on its own subnet and nothing beyond it. The build proxy
// listens there, which is why this needs no new network — the one hole §5 wants
// is the one hole that already exists.
const Gateway = "10.88.0.1"

// Network is the CNI network a build step runs on: the same one a deployment
// gets, with no default route, no NAT and no resolver.
const Network = "nodary-isolated"

// Subnet is the network a build's containers live on, and the only network the
// build proxy answers.
func Subnet() *net.IPNet {
	_, n, err := net.ParseCIDR("10.88.0.0/24")
	if err != nil {
		panic(err) // a constant that parses or a build that does not ship
	}
	return n
}

// ErrNoRuntime is a control plane with no container runtime to build with.
var ErrNoRuntime = errors.New("no container runtime")

// Runner runs a command. Injected so the build can be driven without containerd
// in a test, and so every shell-out in this package is one field rather than
// scattered through it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options is one build.
type Options struct {
	// Descriptor is the derive. Its recipe is the whole input.
	Descriptor backend.Descriptor
	// Tag is what the result is named locally — the reference a deployment
	// pins once R6-10 records it.
	Tag string
	// Run drives nerdctl.
	Run Runner
	// Progress is called before each step, so a half-hour build is not silence.
	Progress func(what string)
	// listen overrides the proxy's bind address in a test, where there is no
	// bridge to bind to.
	listen string
}

// Result is what a build produced.
type Result struct {
	// Image is the local reference the result was tagged with. This is what a
	// deployment pins, and it is content-addressed by convention: the tag
	// carries the recipe digest, so a different recipe is a different tag and
	// no build ever quietly replaces what another produced.
	Image string `json:"image"`
	// Digest is what that reference resolves to in the image store — the
	// "digest of the image it produced" §5 requires the record to carry.
	//
	// Separate from Image because they answer different questions: Image is
	// what to run, Digest is what ran. `nerdctl commit` writes into the local
	// content store rather than pushing, so this is an image ID and not a
	// registry digest; it identifies the bytes on this host, which is where
	// the build happened and the only place it can be attested from.
	Digest string `json:"digest"`
	// Steps is how many ran.
	Steps int `json:"steps"`
	// Reached is the hosts the build was allowed to reach, for the record R6-10
	// writes: a build that installed something names where it came from.
	Reached []string `json:"reached,omitempty"`
}

// Build runs a derive's recipe and leaves a local image.
//
// **Each step is a container, and the result is committed.** Not a Dockerfile:
// BuildKit is not among the pinned components, so a Dockerfile build would need
// a new digest-pinned dependency and a daemon to go with it, where this needs
// only the containerd and nerdctl a control plane already has for LiteLLM.
//
// It is also the shape the schema already has. `steps` is an argv list rather
// than shell text (R6-08), and `nerdctl run <image> <argv>` executes exactly
// that — where a generated Dockerfile would have to render the same argv into
// `RUN` and hope the exec form survived the round trip.
//
// **Nothing is committed from a step that failed.** A non-zero step aborts the
// build with that step's output, so a recipe whose second command fails leaves
// no image at all rather than one carrying half its corrections — which would
// be an image that runs, serves, and is missing the fix it exists for.
func Build(ctx context.Context, o Options) (Result, error) {
	b := o.Descriptor.Backend
	if b.Derive == nil {
		return Result{}, fmt.Errorf("%w: %s is not a derive", backend.ErrInvalid, b.Name)
	}
	if o.Run == nil {
		return Result{}, fmt.Errorf("%w: a derive is built with nerdctl, which this control "+
			"plane has not got", ErrNoRuntime)
	}

	var allow []string
	if u := strings.TrimSpace(b.Derive.IndexURL); u != "" {
		host, err := AllowedFrom(u)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s: %v", backend.ErrInvalid, b.Name, err)
		}
		allow = append(allow, host)
	}
	proxy := NewProxy(allow...)

	// **Bound to any address, and restricted by peer instead.** Listening on
	// the bridge's own address would be the stronger answer and is not
	// available: CNI creates `nodary0` when a container first attaches, and the
	// first container to attach is the step that needs this proxy's address
	// before it starts. On a control plane that is not also a node — which §5
	// makes the ordinary case — 10.88.0.1 is not yet a local address and the
	// bind fails. Proxy.OnlyFrom applies the same restriction a layer up.
	bind := o.listen
	if bind == "" {
		bind = ":0"
	} else {
		// A test binds loopback, where the build's subnet is not where a
		// client comes from. Production never takes this branch.
		proxy.OnlyFrom = nil
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return Result{}, fmt.Errorf("the build proxy cannot bind %s: %w", bind, err)
	}
	srv := &http.Server{Handler: proxy}
	go srv.Serve(ln)
	defer srv.Close()

	// The container reaches the host at the bridge gateway, which exists by the
	// time a step runs because attaching it is what creates the bridge. The
	// listener's own address is a wildcard, so the port is the only part of it
	// worth reading.
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return Result{}, err
	}
	proxyHost := net.JoinHostPort(Gateway, port)
	if o.listen != "" {
		proxyHost = ln.Addr().String()
	}
	proxyURL := "http://" + proxyHost
	timeout := time.Duration(b.Derive.TimeoutS) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Digest-pinned by R6-08's validation, so this cannot resolve to something
	// other than what the recipe names.
	if o.Progress != nil {
		o.Progress("pulling " + b.Derive.From)
	}
	if out, err := o.Run(ctx, "nerdctl", "pull", "--quiet", b.Derive.From); err != nil {
		return Result{}, fmt.Errorf("pulling %s: %v: %s", b.Derive.From, err, tail(out))
	}

	image := b.Derive.From
	for i, step := range b.Derive.Steps {
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("step %d/%d: %s", i+1, len(b.Derive.Steps), step))
		}
		container := fmt.Sprintf("nodary-derive-%s-%d", b.Name, i)

		args := []string{"run", "--name", container,
			"--network", Network,
			// Both spellings: pip reads the lower-case one, a good deal of
			// other tooling reads the upper-case one, and a build that missed
			// the proxy would reach nothing at all rather than reaching out.
			"-e", "https_proxy=" + proxyURL, "-e", "HTTPS_PROXY=" + proxyURL,
			"-e", "http_proxy=" + proxyURL, "-e", "HTTP_PROXY=" + proxyURL,
			// No proxy bypass. Left unset, some tooling excludes localhost and
			// private ranges by default, which is most of what this is keeping
			// a build away from.
			"-e", "no_proxy=", "-e", "NO_PROXY=",
			image,
		}
		args = append(args, strings.Fields(step)...)

		out, runErr := o.Run(ctx, "nerdctl", args...)
		if runErr != nil {
			// Whatever the proxy refused is the more useful answer, and it is
			// usually the cause: pip reports a network failure, and the reason
			// is an allowlist.
			if refusal := proxy.RefusalError(); refusal != nil {
				return Result{}, fmt.Errorf("step %d (%s) failed and %w\n%s",
					i+1, step, refusal, tail(out))
			}
			return Result{}, fmt.Errorf("step %d (%s): %v: %s", i+1, step, runErr, tail(out))
		}

		// Named from the backend rather than from o.Tag: a tag already
		// carrying a `:` would make "<tag>:step-1" an unparseable reference,
		// and the intermediates are this package's business anyway.
		committed := fmt.Sprintf("nodary-derive/%s:step-%d", b.Name, i+1)
		if out, err := o.Run(ctx, "nerdctl", "commit", container, committed); err != nil {
			return Result{}, fmt.Errorf("committing step %d: %v: %s", i+1, err, tail(out))
		}
		// Best effort: a leftover container is untidy, not incorrect, and
		// failing a finished build over one would be worse.
		_, _ = o.Run(ctx, "nerdctl", "rm", "-f", container)
		image = committed
	}

	if out, err := o.Run(ctx, "nerdctl", "tag", image, o.Tag); err != nil {
		return Result{}, fmt.Errorf("tagging %s: %v: %s", o.Tag, err, tail(out))
	}

	// A build that was refused somewhere but still exited zero is one that
	// carried on without a dependency it asked for. §5 wants that to fail.
	if refusal := proxy.RefusalError(); refusal != nil {
		return Result{}, refusal
	}

	digest, err := imageDigest(ctx, o.Run, o.Tag)
	if err != nil {
		return Result{}, err
	}
	return Result{Image: o.Tag, Digest: digest, Steps: len(b.Derive.Steps), Reached: allow}, nil
}

// contentID is an image ID as the store spells one.
var contentID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imageDigest asks the store what a reference resolves to.
//
// `images --no-trunc --quiet` rather than `image inspect`: it is one line of
// output with one meaning, where inspect's schema is a docker-compatibility
// surface whose field spelling has moved between nerdctl releases. The shape is
// checked rather than trusted, because an unexpected line recorded as
// provenance is worse than a build that says it could not tell.
func imageDigest(ctx context.Context, run Runner, ref string) (string, error) {
	out, err := run(ctx, "nerdctl", "images", "--no-trunc", "--quiet", ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %v: %s", ref, err, tail(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); contentID.MatchString(line) {
			return line, nil
		}
	}
	return "", fmt.Errorf("the image store does not say what %s is: %q", ref, tail(out))
}

func tail(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = "…" + s[len(s)-400:]
	}
	return s
}

// Export writes a built image out of the local store, for the mirror to serve
// (R6-15).
//
// No pull first, unlike the bundle's own export: this image was committed here
// and exists nowhere else, so a pull would be an attempt to fetch it from a
// registry that has never seen it.
//
// Written to a temporary name and renamed, because the mirror serves whatever
// is in the cache directory and a node fetching a half-written tar would get a
// `nerdctl load` failure with nothing to say about the cause.
func Export(ctx context.Context, run Runner, ref, dest string) error {
	if run == nil {
		return fmt.Errorf("%w: exporting an image needs nerdctl", ErrNoRuntime)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".nodary-export-*.tar")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	if out, err := run(ctx, "nerdctl", "save", "-o", tmp.Name(), ref); err != nil {
		return fmt.Errorf("exporting %s: %v: %s", ref, err, tail(out))
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
