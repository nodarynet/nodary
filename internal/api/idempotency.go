package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// HeaderIdempotency is docs/specs/09-api.md §2's key, and HeaderReplay says a
// response is one that was made earlier.
const (
	HeaderIdempotency = "Idempotency-Key"
	HeaderReplay      = "X-Nodary-Idempotent-Replay"
)

// maxIdempotentBody bounds what will be buffered to hash and to store. Every
// handler behind this reads a small JSON document; the largest cap any of them
// sets on its own body is 1MB.
const maxIdempotentBody = 1 << 20

// sealKind names what is sealed, as internal/secret requires.
//
// **Sealed, because a stored response can hold a secret.** `POST /tokens`
// returns the plaintext token, and docs/specs/10-cli.md §4 says that is shown
// exactly once and is never readable again. A replay has to be able to return
// it — that is the whole reason a client retries a mint — so the copy must not
// be readable by anything that can read the database. It is sealed under
// secret.key, the same key TOTP seeds and the agent CA private key are under,
// which is what keeps "never readable again" true of the database file.
const sealKind = "idempotency"

// seal and unseal wrap a stored response. A key that cannot be read is a
// failure to store, never a failure to answer: the mutation has committed.
func (s *Server) seal(key, who string, body []byte) ([]byte, error) {
	k, err := s.key()
	if err != nil {
		return nil, err
	}
	return k.Seal(sealKind, key+"\x00"+who, body)
}

func (s *Server) unseal(key, who string, sealed []byte) ([]byte, error) {
	k, err := s.key()
	if err != nil {
		return nil, err
	}
	return k.Open(sealKind, key+"\x00"+who, sealed)
}

// idempotent wraps a POST handler so a repeat returns the first response.
//
// **The row is written before the handler runs, not after.** Recording the
// outcome afterwards would make this a cache of responses, and a cache does not
// stop the case that actually happens: a client whose request timed out retries
// while the first attempt is still working, and both mint a token. Inserting
// first turns the key into an exclusion, and the primary key is what enforces
// it — one writer connection, one winner.
//
// A handler that fails deletes its own row, because a refused request has not
// happened and its key should be free to try again.
//
// A row a dead process left in flight is **not** reclaimed by the next attempt.
// Nobody knows whether that mutation committed, and the safe guess is not "it
// did not" — that is how a second token gets minted. The retry is told to look,
// and the audit chain is where the answer is.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get(HeaderIdempotency))
		if key == "" {
			next(w, r)
			return
		}
		p, err := s.principalOf(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		// Scoped to the caller: a key is a client's own string, so two clients
		// can choose the same one, and handing one caller's response to another
		// is a disclosure rather than a wrong answer.
		who := p.Actor.ID
		if p.User.ID != "" {
			who = p.User.ID
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIdempotentBody))
		if err != nil {
			s.fail(w, r, badRequest("request body is too large to replay idempotently"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		digest := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\n"), body...))
		request := hex.EncodeToString(digest[:])

		prior, err := s.replay.Claim(r.Context(), key, who, request)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if prior != nil {
			body, err := s.unseal(key, who, prior.Body)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			w.Header().Set(HeaderReplay, "true")
			writeRaw(w, prior.Status, body)
			return
		}

		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)

		if rec.status >= 200 && rec.status <= 299 {
			sealed, err := s.seal(key, who, rec.body.Bytes())
			if err != nil {
				// The change has committed and been recorded. Losing the
				// ability to replay it is bad; telling the caller their change
				// failed would be worse and would be untrue.
				s.logf("request %s: sealing the idempotent response: %v", requestID(r), err)
				_ = s.replay.Release(r.Context(), key, who)
				return
			}
			// Best effort. The mutation has committed and is in the chain;
			// failing the response now would tell a client their change did not
			// happen, which is untrue.
			if err := s.replay.Finish(r.Context(), key, who, rec.status, sealed); err != nil {
				s.logf("request %s: recording the idempotent response: %v", requestID(r), err)
			}
			return
		}
		_ = s.replay.Release(r.Context(), key, who)
	}
}

// recorder keeps a handler's response so it can be stored and replayed.
type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (rec *recorder) WriteHeader(status int) {
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recorder) Write(b []byte) (int, error) {
	rec.body.Write(b)
	return rec.ResponseWriter.Write(b)
}

// writeRaw sends a stored response back exactly as it was sent the first time.
func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
