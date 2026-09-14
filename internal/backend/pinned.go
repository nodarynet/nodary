package backend

import (
	"fmt"
	"path"
	"strings"
)

// checkable are the installers whose exact-version form this build can verify,
// and the marker that form uses.
var checkable = map[string]string{
	"pip": "==", "pip3": "==", "pipx": "==", "uv": "==",
	"apt-get": "=", "apt": "=", "apk": "=",
}

// unverifiable is a command that reaches for something this build cannot prove
// is pinned, and the reason in the operator's terms.
//
// **Refused rather than passed.** `require_pinned_derives` exists to make a
// build reproducible, so a step nodary cannot check is precisely the hole it is
// for — and a gate that silently passes what it does not understand is a gate
// that reports compliance it has not established.
var unverifiable = map[string]string{
	"curl":     "fetches a URL whose contents can change",
	"wget":     "fetches a URL whose contents can change",
	"git":      "clones a ref that can move",
	"dnf":      "names versions in a form this build cannot check",
	"yum":      "names versions in a form this build cannot check",
	"microdnf": "names versions in a form this build cannot check",
	"conda":    "names versions in a form this build cannot check",
	"npm":      "spells a scoped name and a version pin with the same character",
	"gem":      "takes the version as a separate argument this build cannot attribute",
	"cargo":    "resolves a version range unless a lockfile says otherwise",
}

// unpinnedFlags name a file this check cannot see into, so what they install is
// pinned only if that file is — which is not something this build can know.
var unpinnedFlags = map[string]string{
	"-r": "a requirements file", "--requirement": "a requirements file",
	"-c": "a constraints file", "--constraint": "a constraints file",
	"-e": "an editable checkout", "--editable": "an editable checkout",
}

// Pinned reports whether a derive satisfies `require_pinned_derives`
// (docs/specs/04-backends.md §5): an index named, and every install step naming
// an exact version.
//
// What `regulated` adds over `default` is that a build is **reproducible**
// rather than merely recorded. A recipe that says `pip install
// opencv-python-headless` produces a different image next month, so the audit
// record R6-10 writes would attest an artifact nobody can rebuild — which is
// the opposite of what the record is for.
func (d Derive) Pinned() error {
	if strings.TrimSpace(d.IndexURL) == "" {
		return fmt.Errorf("%w: derive.index_url is required under a profile that sets "+
			"require_pinned_derives; a build with no named index resolves against whatever "+
			"the container's default is", ErrInvalid)
	}
	for i, step := range d.Steps {
		if err := pinnedStep(step); err != nil {
			return fmt.Errorf("%w: derive.steps[%d] (%s): %v", ErrInvalid, i, step, err)
		}
	}
	return nil
}

func pinnedStep(step string) error {
	argv := strings.Fields(step)
	if len(argv) == 0 {
		return nil
	}
	cmd := path.Base(argv[0])
	// `python -m pip install x` is pip by another spelling, and a gate that
	// missed it would be a gate with a documented way around it.
	if (cmd == "python" || cmd == "python3") && len(argv) > 2 && argv[1] == "-m" {
		cmd, argv = path.Base(argv[2]), argv[2:]
	}
	if why, bad := unverifiable[cmd]; bad {
		return fmt.Errorf("%s %s, so this build cannot establish that the step is pinned", cmd, why)
	}
	marker, known := checkable[cmd]
	if !known {
		// Not an install step by this build's reckoning — `python -c pass`,
		// `ldconfig`. §5 requires *install* steps to name a version, and a
		// command that installs nothing has no version to name.
		return nil
	}
	for _, arg := range argv[1:] {
		if what, ok := unpinnedFlags[arg]; ok {
			return fmt.Errorf("%s names %s this check cannot see into", arg, what)
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// A subcommand (`install`), and paths and URLs that arrived as a
		// flag's separate value. A package name carries neither.
		if isSubcommand(arg) || strings.Contains(arg, "/") {
			continue
		}
		if !strings.Contains(arg, marker) {
			return fmt.Errorf("%s does not name an exact version (want %s%s<version>)",
				arg, arg, marker)
		}
	}
	return nil
}

// isSubcommand is the verb an installer takes before its packages. Listed
// rather than assumed to be argv[1], because `pip --no-cache-dir install x` is
// the same command with the flag moved.
func isSubcommand(arg string) bool {
	switch arg {
	case "install", "add", "update", "upgrade", "reinstall", "pip":
		return true
	}
	return false
}
