package cli

import (
	"fmt"
	"runtime"
)

// goos is runtime.GOOS, indirected so a test can ask what this binary does on
// a host it is not running on. The branch below is unreachable on the machine
// that builds it otherwise, which is the one platform it exists for.
var goos = runtime.GOOS

// requiresLinux refuses a verb that needs systemd, on a host that has none.
//
// **Before preflight, and not skippable.** Preflight already reports the
// platform as a hard failure, but it reports it *alongside* every other check
// that failed as a consequence — a macOS operator asking to install a server
// gets systemd, cgroup v2 and the rest, when the answer is one sentence and
// none of the rest is a problem they can fix. `--skip-preflight` also carries
// past it, into a systemd call whose error names a missing binary rather than
// an unsupported platform.
//
// The wording matches install.sh's check_role_supported deliberately: an
// operator who hits this through the script and then through the binary should
// read the same sentence, and scripts/install_test.go pins that they do.
func requiresLinux(e env, verb string) bool {
	if goos == "linux" {
		return true
	}
	fmt.Fprintf(e.stderr,
		"nodary %s: requires Linux with systemd; this host is %s.\n"+
			"macOS builds provide the operator CLI only — run `nodary node list --server URL`\n"+
			"against a control plane instead (docs/specs/01-install.md §8).\n", verb, goos)
	return false
}
