package evidence

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// chainSegment exports the audit records for the period, and returns the record
// immediately before them.
//
// The anchor is what makes the segment evidence rather than a fragment:
// audit.VerifyFile checks that the first record continues the chain the anchor
// names, so a segment with one proves as much as a whole chain from that point
// on. Without it a reader has consistent records and no reason to believe
// anything preceded them.
func chainSegment(ctx context.Context, db *store.DB, opt Options) ([]byte, *audit.Anchor, error) {
	// Formatted straight to the column's own layout rather than round-tripped
	// through RFC 3339. Go's RFC3339 layout carries no fractional seconds, so
	// formatting an upper bound through it truncates to the whole second and
	// silently drops every record written later in that same second -- which
	// is most of them, on a busy install and in any test.
	from := opt.From.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat)
	to := opt.To.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat)

	var out bytes.Buffer
	if _, err := audit.ExportJSONL(ctx, db, audit.Filter{From: from, To: to, Limit: audit.Unlimited}, &out); err != nil {
		return nil, nil, fmt.Errorf("exporting the chain: %w", err)
	}
	if out.Len() == 0 {
		return out.Bytes(), nil, nil
	}

	first, err := audit.ParseLine(bytes.SplitN(out.Bytes(), []byte("\n"), 2)[0])
	if err != nil {
		return nil, nil, fmt.Errorf("reading the first exported record: %w", err)
	}
	if first.Seq <= 1 {
		// The segment starts at genesis, so there is nothing before it and no
		// anchor to give. That is a whole chain, not a fragment.
		return out.Bytes(), nil, nil
	}
	return out.Bytes(), &audit.Anchor{Seq: first.Seq - 1, Hash: first.PrevHash}, nil
}

// verifySegment runs the verification an assessor would run, and writes what it
// concluded plus the procedure to repeat it without nodary.
func verifySegment(chain []byte, anchor *audit.Anchor) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(verifyHeader)

	if len(chain) == 0 {
		out.WriteString("\nRESULT: no audit records fall in this period.\n")
		return out.Bytes(), nil
	}

	result, err := audit.VerifyBytes(chain, "chain.jsonl", anchor), error(nil)
	if err != nil {
		return nil, fmt.Errorf("verifying the exported segment: %w", err)
	}

	fmt.Fprintf(&out, "\nrecords          %d\nfirst sequence   %d\nlast sequence    %d\n",
		result.Records, result.FirstSeq, result.LastSeq)
	if anchor != nil {
		fmt.Fprintf(&out, "anchored to      seq %d, hash %s\n", anchor.Seq, anchor.Hash)
	} else {
		fmt.Fprintf(&out, "anchored to      genesis: this segment begins at the first record ever written\n")
	}

	switch {
	case result.Break != nil:
		fmt.Fprintf(&out, "\nRESULT: BROKEN at %s\n", result.Break)
	case result.Fragment && !result.Anchored:
		fmt.Fprintf(&out, "\nRESULT: consistent, but unanchored — these records agree with each\n"+
			"other and nothing here proves what preceded them.\n")
	default:
		fmt.Fprintf(&out, "\nRESULT: verified. Every record's hash is the digest of its own\n"+
			"contents including its predecessor's hash, unbroken across the period.\n")
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(&out, "warning: %s\n", w)
	}
	return out.Bytes(), nil
}

const verifyHeader = `nodary audit chain verification
===============================

This file reports what nodary concluded about chain.jsonl in this bundle. It is
not the only way to reach that conclusion, and it is not meant to be trusted on
its own -- the procedure below reproduces it with no nodary installed.

Each record in chain.jsonl is a JSON object whose "hash" is the SHA-256 of the
canonical JSON encoding of the record's other fields, including "prev_hash".
"prev_hash" is the previous record's "hash". So:

  1. Check every member against manifest.sha256:  sha256sum -c manifest.sha256
  2. Check manifest.json is authentic:
       minisign -Vm manifest.json -p nodary-evidence.pub
     The key in nodary-evidence.pub is recorded in the chain at the point it was
     created; that record is the reason to believe the key belongs to this
     install.
  3. Walk chain.jsonl in ascending "seq": each record's "prev_hash" must equal
     the previous record's "hash", with no gaps in "seq".

A segment that does not start at seq 1 is a fragment by design. The anchor below
names the record it must follow, so a fragment with an anchor proves as much as
a whole chain from the anchor onwards.
`
