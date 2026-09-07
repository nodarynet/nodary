package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/minisign"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// Member names, in the order docs/specs/13-evidence.md §2 lists them. Every one
// is always written: a member with no producer yet is empty with its schema
// rather than absent, because a missing file costs an assessor a question and
// an empty one answers it.
const (
	MemberChain       = "chain.jsonl"
	MemberVerify      = "verify.txt"
	MemberControls    = "controls.json"
	MemberControlsMD  = "controls.md"
	MemberRevisions   = "revisions.jsonl"
	MemberNodes       = "nodes.json"
	MemberIdentity    = "identity.jsonl"
	MemberRemediation = "remediation.jsonl"
	MemberManifest    = "manifest.json"
	MemberManifestSig = "manifest.json.minisig"
	MemberDigests     = "manifest.sha256"
	MemberPublicKey   = "nodary-evidence.pub"
	MemberREADME      = "README.txt"
)

// Options bound the reporting period.
type Options struct {
	From, To time.Time
	// Install is the installation id, carried in the manifest so a bundle says
	// which system it came from without an assessor having to open the chain.
	Install string
}

// member is one file on its way into the bundle.
type member struct {
	name string
	body []byte
}

// Bundle is what Build produced, before it is written anywhere.
type Bundle struct {
	Members []member
	Digests map[string]string
	KeyID   string
}

// Build assembles every member and signs the manifest.
//
// It takes an audit.Mutation because producing a bundle is a mutation: the
// signing key may be created here, and an export is itself an event worth
// recording. What it reads is the same data `audit export` reads, which is what
// keeps the free path and the paid path telling the same story.
func Build(ctx context.Context, m audit.Mutation, db *store.DB, k *secret.Key,
	now time.Time, opt Options) (*Bundle, error) {

	key, err := loadKey(ctx, m, k, now)
	if err != nil {
		return nil, err
	}

	chain, anchor, err := chainSegment(ctx, db, opt)
	if err != nil {
		return nil, err
	}
	verification, err := verifySegment(chain, anchor)
	if err != nil {
		return nil, err
	}
	ident, err := identitySegment(ctx, db)
	if err != nil {
		return nil, err
	}
	active, _, err := policy.Active(ctx, db.Read())
	if err != nil {
		return nil, err
	}

	b := &Bundle{KeyID: hex.EncodeToString(key.pub.ID[:])}
	b.add(MemberChain, chain)
	b.add(MemberVerify, verification)
	b.add(MemberIdentity, ident)

	controls, controlsMD := controlIndex(active)
	b.add(MemberControls, controls)
	b.add(MemberControlsMD, controlsMD)

	// Three members whose producers are R2, R4 and R9's remediation half. They
	// are written empty with a status that names why, per 13 §2.
	b.add(MemberRevisions, pending("revision", "configuration revisions arrive with the control plane"))
	b.add(MemberNodes, pendingJSON("nodes", "node approval records arrive with the agent"))
	b.add(MemberRemediation, pending("remediation", "flaw-remediation decisions arrive with the advisory feed"))

	b.add(MemberPublicKey, []byte(minisign.EncodePublicKey(key.pub)))
	b.add(MemberREADME, readme(opt, active.Name))

	manifest, err := b.manifest(opt, now)
	if err != nil {
		return nil, err
	}
	b.add(MemberManifest, manifest)
	b.add(MemberDigests, b.digestFile())

	comment := fmt.Sprintf("nodary evidence bundle %s to %s, install %s",
		opt.From.UTC().Format(time.DateOnly), opt.To.UTC().Format(time.DateOnly), opt.Install)
	b.add(MemberManifestSig, []byte(minisign.Sign(key.priv, key.pub.ID, manifest, comment)))

	m.Detail("members", len(b.Members))
	m.Detail("evidence_key_id", b.KeyID)
	return b, nil
}

func (b *Bundle) add(name string, body []byte) {
	if b.Digests == nil {
		b.Digests = map[string]string{}
	}
	b.Members = append(b.Members, member{name: name, body: body})
	sum := sha256.Sum256(body)
	b.Digests[name] = hex.EncodeToString(sum[:])
}

// manifest lists every member written so far with its digest.
//
// It lists members rather than fixing a schema per member, so a member that
// gains rows in a later release is not a format change.
func (b *Bundle) manifest(opt Options, now time.Time) ([]byte, error) {
	type entry struct {
		Name   string `json:"name"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
		// Records is the row count for a JSONL member, so an empty one is
		// distinguishable from a broken one. A zero-byte file answers neither
		// question, and "is this empty because nothing happened" is the first
		// thing an assessor asks about a member with no content.
		Records *int `json:"records,omitempty"`
	}
	doc := struct {
		Schema    int     `json:"schema"`
		Product   string  `json:"product"`
		Install   string  `json:"install"`
		From      string  `json:"from"`
		To        string  `json:"to"`
		Generated string  `json:"generated"`
		Members   []entry `json:"members"`
	}{
		Schema: 1, Product: "nodary", Install: opt.Install,
		From:      opt.From.UTC().Format(time.RFC3339),
		To:        opt.To.UTC().Format(time.RFC3339),
		Generated: now.UTC().Format(time.RFC3339),
	}
	for _, mem := range b.Members {
		e := entry{Name: mem.name, Bytes: len(mem.body), SHA256: b.Digests[mem.name]}
		if strings.HasSuffix(mem.name, ".jsonl") {
			n := bytes.Count(mem.body, []byte("\n"))
			e.Records = &n
		}
		doc.Members = append(doc.Members, e)
	}
	sort.Slice(doc.Members, func(i, j int) bool { return doc.Members[i].Name < doc.Members[j].Name })

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("rendering the manifest: %w", err)
	}
	return append(out, '\n'), nil
}

// digestFile is what `sha256sum -c` reads, so the check needs no tool nodary
// wrote and no JSON parser.
func (b *Bundle) digestFile() []byte {
	names := make([]string, 0, len(b.Digests))
	for n := range b.Digests {
		names = append(names, n)
	}
	sort.Strings(names)

	var out bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&out, "%s  %s\n", b.Digests[n], n)
	}
	return out.Bytes()
}

// WriteTarGz writes the bundle.
func (b *Bundle) WriteTarGz(w io.Writer, now time.Time) error {
	zw := gzip.NewWriter(w)
	tw := tar.NewWriter(zw)
	for _, mem := range b.Members {
		if err := tw.WriteHeader(&tar.Header{
			Name: mem.name, Mode: 0o644, Size: int64(len(mem.body)),
			ModTime: now.UTC(), Format: tar.FormatPAX,
		}); err != nil {
			return fmt.Errorf("writing %s: %w", mem.name, err)
		}
		if _, err := tw.Write(mem.body); err != nil {
			return fmt.Errorf("writing %s: %w", mem.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

// pending is an empty JSONL member: one object saying the category exists and
// this install has nothing in it yet.
func pending(kind, why string) []byte {
	line, _ := json.Marshal(map[string]any{"schema": 1, "kind": kind, "status": "pending", "detail": why})
	return append(line, '\n')
}

func pendingJSON(kind, why string) []byte {
	doc, _ := json.MarshalIndent(map[string]any{
		"schema": 1, "kind": kind, "status": "pending", "detail": why, kind: []any{},
	}, "", "  ")
	return append(doc, '\n')
}

// identitySegment is the user and token lifecycle.
func identitySegment(ctx context.Context, db *store.DB) ([]byte, error) {
	users, err := identity.List(ctx, db.Read(), true)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	tokens, err := identity.ListTokens(ctx, db.Read(), "")
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}

	var out bytes.Buffer
	for _, u := range users {
		line, err := json.Marshal(map[string]any{
			"kind": "user", "id": u.ID, "name": u.Name, "role": string(u.Role),
			"state": string(u.State), "totp_enrolled": u.TOTPEnrolled,
			"created_at": u.CreatedAt.UTC().Format(time.RFC3339),
		})
		if err != nil {
			return nil, err
		}
		out.Write(append(line, '\n'))
	}
	for _, t := range tokens {
		// The prefix, never a hash and never a secret: it is what makes this
		// record and a revocation refer to the same credential.
		line, err := json.Marshal(map[string]any{
			"kind": "token", "id": t.ID, "user_id": t.UserID, "token_kind": string(t.Kind),
			"prefix": t.Prefix, "unattended": t.Unattended, "revoked": t.Revoked(),
			"created_at": t.CreatedAt.UTC().Format(time.RFC3339),
		})
		if err != nil {
			return nil, err
		}
		out.Write(append(line, '\n'))
	}
	return out.Bytes(), nil
}
