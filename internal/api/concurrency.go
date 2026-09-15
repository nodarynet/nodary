package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/config"
)

// HeaderIfMatch and HeaderETag carry dev/specs/09-api.md §2's concurrency
// control: "Mutating endpoints on a versioned object accept If-Match with the
// object's current revision; a mismatch returns 409."
const (
	HeaderIfMatch = "If-Match"
	HeaderETag    = "ETag"
)

// ErrRevisionChanged is a mutation whose If-Match no longer matches.
var ErrRevisionChanged = errors.New("the configuration changed since you read it")

// revisionETag is the version of every config-backed object.
//
// **One version for the whole configuration, not one per object.** Models,
// deployments, routes, limits and the active policy profile are all read out of
// a single `config.Snapshot`, and every change to any of them records one
// revision (R2-11) — so the revision chain is already the version, and inventing
// a per-object counter beside it would create a second answer to the same
// question that can disagree with the first.
//
// The cost is that it is conservative: an administrator editing a route is
// refused when somebody else changed a *limit* in between. That is the right
// way to be wrong here. The lost update this prevents is silent, and the
// failure it causes instead is a 409 that says exactly what to do.
func revisionETag(seq int64) string { return `"` + strconv.FormatInt(seq, 10) + `"` }

// setRevisionETag stamps a read with the revision it saw, so a client has
// something to send back. Best-effort: a read must not fail because the version
// could not be stamped on it.
func setRevisionETag(ctx context.Context, w http.ResponseWriter, q config.Querier) {
	if seq, err := config.LatestSeq(ctx, q); err == nil {
		w.Header().Set(HeaderETag, revisionETag(seq))
	}
}

// checkIfMatch refuses a mutation whose If-Match no longer holds.
//
// **Called inside the mutation's own transaction**, never before it. Read
// outside, two administrators could both see revision N, both pass this, and
// both apply — which is the exact race the header exists to close. internal/store
// caps the writer pool at one connection, so a check inside the transaction is
// serialized against every other writer by construction.
//
// An absent header is not a failure. 09 §2 makes If-Match something endpoints
// *accept*, not something they demand: a client that has not read the object has
// nothing to have raced with, and requiring it would break every caller that
// simply sets a value.
func checkIfMatch(ctx context.Context, r *http.Request, q config.Querier) error {
	want := strings.TrimSpace(r.Header.Get(HeaderIfMatch))
	if want == "" {
		return nil
	}
	have, err := config.LatestSeq(ctx, q)
	if err != nil {
		return err
	}
	// RFC 9110: "*" matches any current representation. Here that means "apply
	// as long as a configuration exists", which is what a client that wants the
	// header's shape without its guarantee is asking for.
	if want == "*" {
		return nil
	}
	// Both the quoted form an ETag is sent in and the bare number, because a
	// client that echoes what it was given and one that pulled the number out
	// of the JSON are both being reasonable.
	for _, candidate := range strings.Split(want, ",") {
		if strings.Trim(strings.TrimSpace(candidate), `"`) == strconv.FormatInt(have, 10) {
			return nil
		}
	}
	return fmt.Errorf("%w: it is at revision %d, and you sent %s — re-read it and decide again",
		ErrRevisionChanged, have, want)
}
