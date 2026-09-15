package cli

import (
	"path/filepath"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/dataplane"
)

// selectedPlane is the data plane this host runs, read from server.toml.
//
// One reader, because every verb that touches the plane — install, sync,
// upgrade, status, uninstall, the gateway itself — has to reach the same answer
// from the same file, and six readers is six chances to disagree about which
// process is serving inference.
//
// A directory with no server.toml reads as the default: that is a node, or a
// test's temporary tree, and it is the same rule an absent `data_plane` key
// follows. A file that names a plane this build does not have was already
// refused by api.LoadServerConfig, so a file that loads cannot select a bad one.
func selectedPlane(dir string) dataplane.Plane {
	c, err := api.LoadServerConfig(filepath.Join(dir, "server.toml"))
	if err != nil {
		return dataplane.Default()
	}
	p, err := dataplane.Select(c.DataPlane)
	if err != nil {
		return dataplane.Default()
	}
	return p
}

// dataPlaneUnits is every plane's unit, for the lists that must act on a host
// whichever one it runs — restarting what moved, and stopping a unit left by a
// plane the host has since switched away from. First, because the data plane
// comes before the API that proxies to it in every ordering nodary uses.
func dataPlaneUnits() []string {
	out := []string{}
	for _, p := range dataplane.All() {
		out = append(out, p.Unit)
	}
	return out
}
