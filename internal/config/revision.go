package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/canonical"
)

// genesis is what the first revision claims to follow. Same shape as the audit
// chain's: a fixed, obviously-not-a-hash value, so "this is the first" is
// something the chain says rather than something a reader infers from a NULL.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Revision is one recorded configuration.
type Revision struct {
	Seq           int64
	TS            time.Time
	Actor         string
	Justification string
	Snapshot      *Snapshot
	PrevHash      string
	Hash          string
}

// ErrNoRevision is returned for a sequence number nothing wrote.
var ErrNoRevision = errors.New("no such revision")

// preimage is what gets hashed. It is a separate type from Revision so the
// hashed fields are a list somebody can read, rather than whatever Revision
// happens to have today — adding a field to Revision must not silently change
// every hash in the chain.
type preimage struct {
	Seq           int64     `json:"seq"`
	TS            string    `json:"ts"`
	Actor         string    `json:"actor"`
	Justification string    `json:"justification"`
	Snapshot      *Snapshot `json:"snapshot"`
	PrevHash      string    `json:"prev_hash"`
}

func hashOf(seq int64, ts time.Time, actor, justification string, s *Snapshot, prev string) (string, error) {
	return canonical.HashHex(preimage{
		Seq: seq, TS: ts.UTC().Format(audit.TimeFormat), Actor: actor,
		Justification: justification, Snapshot: s, PrevHash: prev,
	})
}

// Record snapshots the configuration and appends it to the chain.
//
// It takes an audit.Mutation rather than a transaction, so a revision cannot be
// written without an audit record: the revision carries the state, the audit
// record carries the act, and neither is much use alone. Being in the same
// transaction is what stops the two disagreeing — a revision written separately
// can be lost while the change survives, and then history says the current
// state was never applied.
//
// Call it *after* the change it describes. A revision answers "what was true
// once this landed", which is what a rollback target has to be.
func Record(ctx context.Context, m audit.Mutation, now time.Time, actor, justification string) (Revision, error) {
	tx := m.Tx()
	s, err := Read(ctx, tx)
	if err != nil {
		return Revision{}, err
	}

	var (
		lastSeq  int64
		lastHash sql.NullString
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT coalesce(max(seq), 0), (SELECT hash FROM revision ORDER BY seq DESC LIMIT 1) FROM revision`,
	).Scan(&lastSeq, &lastHash); err != nil {
		return Revision{}, fmt.Errorf("reading the revision chain: %w", err)
	}
	prev := genesis
	if lastHash.Valid {
		prev = lastHash.String
	}

	r := Revision{
		Seq: lastSeq + 1, TS: now.UTC().Truncate(time.Millisecond),
		Actor: actor, Justification: justification, Snapshot: s, PrevHash: prev,
	}
	if r.Hash, err = hashOf(r.Seq, r.TS, r.Actor, r.Justification, r.Snapshot, r.PrevHash); err != nil {
		return Revision{}, fmt.Errorf("hashing the revision: %w", err)
	}

	body, err := json.Marshal(s)
	if err != nil {
		return Revision{}, fmt.Errorf("encoding the snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO revision (seq, ts, actor, justification, snapshot_json, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.Seq, r.TS.Format(audit.TimeFormat), r.Actor, nullable(r.Justification),
		string(body), r.PrevHash, r.Hash); err != nil {
		return Revision{}, fmt.Errorf("writing revision %d: %w", r.Seq, err)
	}

	m.Detail("revision", r.Seq)
	return r, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Get reads one revision. Seq 0 means the latest.
func Get(ctx context.Context, q Querier, seq int64) (Revision, error) {
	query := `SELECT seq, ts, actor, coalesce(justification, ''), snapshot_json, prev_hash, hash
		FROM revision WHERE seq = ?`
	args := []any{seq}
	if seq <= 0 {
		query = `SELECT seq, ts, actor, coalesce(justification, ''), snapshot_json, prev_hash, hash
			FROM revision ORDER BY seq DESC LIMIT 1`
		args = nil
	}

	var (
		r    Revision
		ts   string
		body string
	)
	err := q.QueryRowContext(ctx, query, args...).
		Scan(&r.Seq, &ts, &r.Actor, &r.Justification, &body, &r.PrevHash, &r.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		if seq <= 0 {
			return Revision{}, fmt.Errorf("%w: nothing has been recorded yet", ErrNoRevision)
		}
		return Revision{}, fmt.Errorf("%w: %d", ErrNoRevision, seq)
	}
	if err != nil {
		return Revision{}, fmt.Errorf("reading revision %d: %w", seq, err)
	}
	if r.TS, err = time.Parse(audit.TimeFormat, ts); err != nil {
		return Revision{}, fmt.Errorf("revision %d has an unreadable timestamp %q: %w", r.Seq, ts, err)
	}
	if err := json.Unmarshal([]byte(body), &r.Snapshot); err != nil {
		return Revision{}, fmt.Errorf("revision %d has an unreadable snapshot: %w", r.Seq, err)
	}
	return r, nil
}

// List returns revisions newest first.
func List(ctx context.Context, q Querier, limit int) ([]Revision, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := q.QueryContext(ctx,
		`SELECT seq, ts, actor, coalesce(justification, ''), prev_hash, hash
		 FROM revision ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("listing revisions: %w", err)
	}
	defer rows.Close()

	var out []Revision
	for rows.Next() {
		var r Revision
		var ts string
		if err := rows.Scan(&r.Seq, &ts, &r.Actor, &r.Justification, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		r.TS, _ = time.Parse(audit.TimeFormat, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Verify walks the chain and reports the first break by sequence number.
//
// Same contract as `audit verify`: naming the first break is what makes a
// report actionable, and everything after a break is unverifiable anyway.
func Verify(ctx context.Context, q Querier) (int64, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT seq, ts, actor, coalesce(justification, ''), snapshot_json, prev_hash, hash
		 FROM revision ORDER BY seq`)
	if err != nil {
		return 0, fmt.Errorf("reading the revision chain: %w", err)
	}
	defer rows.Close()

	var (
		count int64
		want        = genesis
		next  int64 = 1
	)
	for rows.Next() {
		var (
			r        Revision
			ts, body string
		)
		if err := rows.Scan(&r.Seq, &ts, &r.Actor, &r.Justification, &body, &r.PrevHash, &r.Hash); err != nil {
			return count, err
		}
		if r.Seq != next {
			return count, fmt.Errorf("revision %d is missing: %d is followed by %d", next, next-1, r.Seq)
		}
		if r.PrevHash != want {
			return count, fmt.Errorf("revision %d does not follow %d", r.Seq, r.Seq-1)
		}
		parsed, err := time.Parse(audit.TimeFormat, ts)
		if err != nil {
			return count, fmt.Errorf("revision %d has an unreadable timestamp: %w", r.Seq, err)
		}
		if err := json.Unmarshal([]byte(body), &r.Snapshot); err != nil {
			return count, fmt.Errorf("revision %d has an unreadable snapshot: %w", r.Seq, err)
		}
		got, err := hashOf(r.Seq, parsed, r.Actor, r.Justification, r.Snapshot, r.PrevHash)
		if err != nil {
			return count, err
		}
		if got != r.Hash {
			return count, fmt.Errorf("revision %d has been altered", r.Seq)
		}
		want, next, count = r.Hash, r.Seq+1, count+1
	}
	return count, rows.Err()
}

// Changes lists the differences between two snapshots, as lines.
//
// Deliberately a list of lines rather than a structured diff: `config diff` is
// read by a person deciding whether to apply something, and R2-12 asks for what
// changed rather than for a machine-consumable delta.
func Changes(from, to *Snapshot) []string {
	var out []string
	out = append(out, diffKeyed("node", keyNodes(from), keyNodes(to))...)
	out = append(out, diffKeyed("model", keyModels(from), keyModels(to))...)
	out = append(out, diffKeyed("deployment", keyDeployments(from), keyDeployments(to))...)
	out = append(out, diffKeyed("route", keyRoutes(from), keyRoutes(to))...)
	out = append(out, diffKeyed("limits", keyLimits(from), keyLimits(to))...)

	fp, tp := "none", "none"
	if from != nil && from.Policy != nil {
		fp = from.Policy.Name + "@" + short(from.Policy.Source)
	}
	if to != nil && to.Policy != nil {
		tp = to.Policy.Name + "@" + short(to.Policy.Source)
	}
	if fp != tp {
		out = append(out, fmt.Sprintf("~ policy %s -> %s", fp, tp))
	}
	return out
}

func short(s string) string {
	h, err := canonical.HashHex(s)
	if err != nil || len(h) < 8 {
		return "?"
	}
	return h[:8]
}

// diffKeyed reports additions, removals and changes between two keyed sets.
func diffKeyed(kind string, from, to map[string]string) []string {
	var out []string
	for k, v := range to {
		old, had := from[k]
		switch {
		case !had:
			out = append(out, fmt.Sprintf("+ %s %s", kind, k))
		case old != v:
			out = append(out, fmt.Sprintf("~ %s %s", kind, k))
		}
	}
	for k := range from {
		if _, still := to[k]; !still {
			out = append(out, fmt.Sprintf("- %s %s", kind, k))
		}
	}
	slices.Sort(out)
	return out
}

func render(v any) string {
	b, err := canonical.Encode(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func keyNodes(s *Snapshot) map[string]string {
	m := map[string]string{}
	if s == nil {
		return m
	}
	for _, n := range s.Nodes {
		m[n.Name] = render(n)
	}
	return m
}

func keyModels(s *Snapshot) map[string]string {
	m := map[string]string{}
	if s == nil {
		return m
	}
	for _, x := range s.Models {
		m[x.ID] = render(x)
	}
	return m
}

func keyDeployments(s *Snapshot) map[string]string {
	m := map[string]string{}
	if s == nil {
		return m
	}
	for _, d := range s.Deployments {
		m[d.ID] = render(d)
	}
	return m
}

func keyRoutes(s *Snapshot) map[string]string {
	m := map[string]string{}
	if s == nil {
		return m
	}
	for _, r := range s.Routes {
		m[r.Name] = render(r)
	}
	return m
}

func keyLimits(s *Snapshot) map[string]string {
	m := map[string]string{}
	if s == nil {
		return m
	}
	for _, l := range s.Limits {
		m[strings.Join([]string{l.SubjectKind, l.SubjectID}, "/")] = render(l)
	}
	return m
}

// LatestSeq is the sequence number of the newest revision, or 0 for a
// configuration nobody has changed yet.
//
// It is what the agent long-poll compares against
// (docs/plans/R4a-agent-protocol.md §6): the revision chain already advances on
// every configuration change, so a node needs no counter of its own.
func LatestSeq(ctx context.Context, q Querier) (int64, error) {
	var seq int64
	if err := q.QueryRowContext(ctx,
		`SELECT coalesce(max(seq), 0) FROM revision`).Scan(&seq); err != nil {
		return 0, fmt.Errorf("reading the revision chain: %w", err)
	}
	return seq, nil
}
