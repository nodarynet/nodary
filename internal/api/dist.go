package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// distName is what a mirror path may be: the shape components.ArtifactName
// produces and nothing else.
//
// The check is a whitelist rather than a traversal filter. This handler joins a
// caller-supplied string to a directory path, and "reject what looks dangerous"
// is the design that keeps needing another exclusion; "accept only what we
// ourselves generate" does not.
func distName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	// `..` is excluded by the above only in combination with a separator, which
	// cannot appear — but a name that is entirely dots is still not one of ours.
	return !strings.HasPrefix(s, ".")
}

// serveDist is the mirror of docs/specs/01-install.md §3.
//
// The control plane resolves components once and serves that cache to every
// node, so **only the control-plane host ever contacts an upstream source** and
// GPU hosts bootstrap with no internet and no registry access. That is the same
// property docs/specs/03-agent.md §5 asserts at runtime, applied to install
// time: a node that curls GitHub to install containerd is a node with egress,
// on the day it is least supervised.
//
// Behind mTLS like the rest of `/agent/`, so the mirror is not an open file
// server on the control plane's port. A node that has not enrolled has no
// business fetching from it.
func (s *Server) serveDist(w http.ResponseWriter, r *http.Request) {
	if _, err := s.agentNode(r); err != nil {
		s.fail(w, r, err)
		return
	}
	name := r.PathValue("name")
	if !distName(name) {
		s.fail(w, r, badRequest("%q is not an artifact name", name))
		return
	}
	if s.dist == "" {
		s.fail(w, r, badRequest("this control plane has no component cache; run `nodary components fetch`"))
		return
	}

	path := filepath.Join(s.dist, name)
	f, err := os.Open(path)
	if err != nil {
		// 404 with the name, and no directory listing: a node asking for
		// something the cache does not hold has a manifest this control plane
		// has not resolved, and saying which artifact is the useful half.
		s.fail(w, r, notFound("the component cache holds no %s", name))
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		s.fail(w, r, notFound("the component cache holds no %s", name))
		return
	}

	// The node verifies the digest against its own embedded manifest, so this
	// serves bytes and makes no claim about them. Neither side trusts the
	// other's word (docs/plans/R5a-components-and-units.md §1).
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// DistDirName is the cache under the data directory.
const DistDirName = "dist"

// DistDir is where a control plane keeps resolved components.
// docs/specs/01-install.md §12.
func DistDir(dataDir string) string { return filepath.Join(dataDir, DistDirName) }
