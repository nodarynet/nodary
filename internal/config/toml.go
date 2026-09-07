package config

import (
	"bytes"
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
)

// EncodeTOML renders a snapshot as the file `config export` writes.
//
// docs/specs/08-data-model.md §2: "The database is authoritative; the export is
// a convenience." So this is a rendering, not a second source of truth, and it
// is TOML rather than the JSON the chain hashes because a human edits this one
// and TOML has comments.
func EncodeTOML(w io.Writer, s *Snapshot) error {
	if _, err := io.WriteString(w, tomlHeader); err != nil {
		return err
	}
	enc := toml.NewEncoder(w)
	enc.Indent = "  "
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("rendering the configuration: %w", err)
	}
	return nil
}

const tomlHeader = `# nodary configuration, exported.
#
# This is desired state: what somebody decided. It carries no observed state --
# no heartbeats, no staging progress, no deployment health -- because replaying
# those onto a rebuilt control plane would assert things that are not true.
#
# The database is authoritative and this file is a convenience. Read it back
# with ` + "`nodary config apply -f`" + `; objects present here are created or
# updated, and objects absent from it are left alone unless --prune is passed.
#
# A node cannot be created from here. Nodes join by enrolling.

`

// DecodeTOML reads a configuration file.
//
// Unknown keys are refused, for the same reason a policy profile refuses them
// (docs/plans/R1d-policy.md): this file is reviewed by reading it, and a key
// nobody applies is a decision an operator believes is in force.
func DecodeTOML(b []byte) (*Snapshot, error) {
	var s Snapshot
	md, err := toml.Decode(string(b), &s)
	if err != nil {
		return nil, fmt.Errorf("reading the configuration: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys in the configuration: %v — a file nobody fully applies is a decision somebody wrongly believes is in force", keys)
	}
	normalise(&s)
	return &s, nil
}

// normalise fills in what a hand-written file may leave out, so a snapshot read
// from a file compares equal to one read from the database.
func normalise(s *Snapshot) {
	if s.Nodes == nil {
		s.Nodes = []Node{}
	}
	if s.Models == nil {
		s.Models = []Model{}
	}
	if s.Deployments == nil {
		s.Deployments = []Deployment{}
	}
	if s.Routes == nil {
		s.Routes = []Route{}
	}
	if s.Limits == nil {
		s.Limits = []Limit{}
	}
	if s.Grants == nil {
		s.Grants = []Grant{}
	}
	for i := range s.Nodes {
		if s.Nodes[i].RebootPolicy == "" {
			s.Nodes[i].RebootPolicy = "manual-console"
		}
		if s.Nodes[i].Constraints == "" {
			s.Nodes[i].Constraints = "{}"
		}
	}
	for i := range s.Models {
		if s.Models[i].Hints == "" {
			s.Models[i].Hints = "{}"
		}
	}
	for i := range s.Deployments {
		if s.Deployments[i].GPUs == nil {
			s.Deployments[i].GPUs = []int{}
		}
		if s.Deployments[i].Params == "" {
			s.Deployments[i].Params = "{}"
		}
		if s.Deployments[i].ExtraArgs == "" {
			s.Deployments[i].ExtraArgs = "[]"
		}
	}
	for i := range s.Routes {
		if s.Routes[i].Strategy == "" {
			s.Routes[i].Strategy = "round-robin"
		}
		if s.Routes[i].Members == nil {
			s.Routes[i].Members = []RouteMember{}
		}
		for j := range s.Routes[i].Members {
			if s.Routes[i].Members[j].Weight == 0 {
				s.Routes[i].Members[j].Weight = 1
			}
		}
	}
}

// RenderTOML is EncodeTOML into a buffer, for callers that want the bytes.
func RenderTOML(s *Snapshot) ([]byte, error) {
	var b bytes.Buffer
	if err := EncodeTOML(&b, s); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
