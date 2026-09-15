// Package dataplane is the OpenAI-compatible process the gateway proxies to.
//
// dev/specs/06-gateway.md §7 states one contract two implementations satisfy:
// nodary owns identity, quota, metering and audit, and the data plane owns
// OpenAI compatibility, routing, retries and fallbacks. Everything specific to
// one of them — its name, its unit, its files, the header it answers with, how
// its configuration is rendered and what that rendering must never say — lives
// in this package and nowhere else.
//
// **That containment is the point, and it is tested.** Before this package
// existed, LiteLLM was named in nine places across the gateway, the installer
// and the CLI, and a second plane would have turned every one of them into a
// conditional. TestNothingOutsideThisPackageNamesAPlane is what keeps the
// tenth from being written.
package dataplane

import (
	"errors"
	"fmt"
	"strings"
)

// Plane is one data plane, described completely.
//
// A struct of data and two functions rather than an interface: the differences
// between implementations are names, a file and a renderer, and a struct value
// is what a test can compare field by field. An interface here would be one
// implementation per method set with nothing to dispatch on.
type Plane struct {
	// Name is what `data_plane` in server.toml says, and what `nodary status`
	// prints. Lowercase, because an operator types it.
	Name string
	// Component is the entry in the component manifest that pins this plane's
	// image. `nodary upgrade` moves it; `--check` reports it.
	Component string
	// Unit is the systemd unit, and UnitBody what an install writes into it.
	// The body lives here rather than beside the other units because every
	// line of it is plane-specific — the container name, the mount, the
	// environment file, the arguments and the port are all this plane's.
	Unit     string
	UnitBody string
	// ConfigFile is the rendered configuration, in the config directory, and
	// EnvFile is where the image pin lives beside it. Two files because they
	// have two writers: `gateway sync` owns the first and `upgrade` the
	// second, and an upgrade that rewrote the configuration would replace a
	// control plane's routes with the empty list a first install starts from.
	ConfigFile string
	EnvFile    string
	// ImageVar is the variable inside EnvFile the unit expands.
	ImageVar string
	// AppliedName is the marker under /run/nodary recording the configuration
	// the running process was started with. Per plane, so switching planes
	// cannot leave one reading the other's digest and skipping a restart.
	AppliedName string
	// ServedHeader is the response header carrying the id of the member that
	// actually served a request. Without it a usage row names no deployment,
	// no node and no GPU, which is most of what metering is for at this size.
	ServedHeader string
	// Render produces the configuration file's bytes, and Assert checks those
	// bytes before anything writes or uses them. Assert reads the rendering
	// rather than trusting the renderer, because a control whose failure looks
	// exactly like success has to be checked on its output.
	Render func(Config) []byte
	Assert func([]byte) error
}

// Config is what a plane is rendered from: the ready members of every route,
// and the one credential the gateway authenticates with.
//
// Neutral, and not the shape of any one plane's file. It is generated from
// routes and deployments rather than maintained by hand, because the two would
// drift and the drift would be invisible: a route whose deployment moved would
// keep proxying to an address nothing serves.
type Config struct {
	Members   []Member
	MasterKey string
}

// Member is one route, pointed at one deployment.
type Member struct {
	Name    string
	APIBase string
	Model   string
	// Weight is the member's share of the traffic across a route's members.
	// Zero means "not stated", and the plane's own default applies.
	//
	// config.RouteMember has carried this since routes existed and nothing
	// rendered it, so `nodary route set --add` wrote a weight that changed
	// nothing — a configuration field an operator can set and the product
	// ignores is worse than one that does not exist.
	Weight int
	// ID is the deployment's id, rendered so that the plane hands it back on
	// every response in ServedHeader.
	//
	// A route may have several members and the plane picks between them, so
	// nothing in a request says which deployment served it. Naming our own id
	// here is what makes the one component that made the choice tell us what
	// it chose.
	ID string
}

// ErrUnknownPlane is a `data_plane` naming something this build does not have.
var ErrUnknownPlane = errors.New("unknown data plane")

// planes are the implementations, in the order `nodary status` would list them.
var planes = []Plane{LiteLLM}

// Default is what a server.toml with no `data_plane` key runs.
//
// LiteLLM, and it must stay LiteLLM: every install that predates the selector
// runs it, and a missing key has to describe what is actually on the host
// rather than what a later release would prefer. A fresh install writes the
// key explicitly, so the default is read only by hosts that already exist.
func Default() Plane { return LiteLLM }

// Select resolves what server.toml says, and refuses anything else.
//
// Empty is the default rather than an error. A name this build does not have
// is refused by name, because the alternative — falling back — would start the
// wrong data plane on a host whose operator wrote what they wanted.
func Select(name string) (Plane, error) {
	if strings.TrimSpace(name) == "" {
		return Default(), nil
	}
	for _, p := range planes {
		if p.Name == name {
			return p, nil
		}
	}
	return Plane{}, fmt.Errorf("%w: %q; this build has %s",
		ErrUnknownPlane, name, strings.Join(Names(), ", "))
}

// Names is every plane this build can run.
func Names() []string {
	out := make([]string, len(planes))
	for i, p := range planes {
		out[i] = p.Name
	}
	return out
}

// All is every plane, for the places that must act on a host whichever one it
// runs — removing unit files, and searching for one left by a plane the host
// has since switched away from.
func All() []Plane { return append([]Plane(nil), planes...) }
