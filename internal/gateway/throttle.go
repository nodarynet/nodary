package gateway

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/observed"
)

// docs/specs/06-gateway.md §4. Four limits, each with its own unit, applied per
// user, per role and globally.
//
// **Every applicable limit binds, and the most restrictive wins.** A user with
// `rpm = 600` sitting under a global `rpm = 100` gets 100. The alternative —
// most specific overrides — would make a global ceiling escapable by giving
// somebody a per-user limit, which is the opposite of what a ceiling is for,
// and it would leave an administrator unable to cap the fleet at all without
// editing every user. The cost is that a per-user limit cannot *raise* anyone
// above a global one, which is the correct trade for a control somebody writes
// down in a system security plan.
const (
	perMinute = time.Minute
	// dailyResetHour is 06 §4's "configured UTC hour". There is no setting for
	// it yet, so midnight UTC is the value and this constant is where it moves
	// to when there is one.
	dailyResetHour = 0
)

// limit is one ceiling and the subject that set it, because a 429 that does not
// say whose limit was hit sends a user to the wrong administrator.
type limit struct {
	value   int
	subject string
}

// tighten keeps the smaller of two ceilings. Zero means unlimited, so it never
// wins against a real number.
func (l *limit) tighten(v int, subject string) {
	if v <= 0 {
		return
	}
	if l.value == 0 || v < l.value {
		l.value, l.subject = v, subject
	}
}

// limits is what applies to one principal, already reduced.
type limits struct {
	rpm, tpm, daily, concurrent limit
}

func (l limits) none() bool {
	return l.rpm.value == 0 && l.tpm.value == 0 && l.daily.value == 0 && l.concurrent.value == 0
}

// limitsFor reduces every row that applies to this caller into one set.
//
// A user row is matched on the name *and* on the id. `limits set --subject
// alice` stores whatever an operator typed and nothing validates it against the
// user table, so matching only one of the two would silently enforce nothing —
// which is the failure this whole task exists to end.
func (s *Server) limitsFor(ctx context.Context, p identity.Principal) (limits, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT subject_kind, subject_id, rpm, tpm, daily_tokens, max_concurrent
		   FROM limits
		  WHERE (subject_kind = 'user' AND subject_id IN (?, ?))
		     OR (subject_kind = 'role' AND subject_id = ?)
		     OR  subject_kind = 'global'`,
		p.User.Name, p.User.ID, string(p.Role))
	if err != nil {
		return limits{}, err
	}
	defer rows.Close()

	var out limits
	for rows.Next() {
		var kind, id string
		var rpm, tpm, daily, concurrent sql.NullInt64
		if err := rows.Scan(&kind, &id, &rpm, &tpm, &daily, &concurrent); err != nil {
			return limits{}, err
		}
		subject := kind + ":" + id
		if kind == "global" {
			subject = "global"
		}
		out.rpm.tighten(int(rpm.Int64), subject)
		out.tpm.tighten(int(tpm.Int64), subject)
		out.daily.tighten(int(daily.Int64), subject)
		out.concurrent.tighten(int(concurrent.Int64), subject)
	}
	return out, rows.Err()
}

// refusal is what a 429 says. 06 §4: a bare 429 tells a user nothing
// actionable, so each of these reaches the body.
type refusal struct {
	Limit    string `json:"limit"`
	Subject  string `json:"subject"`
	Value    int    `json:"limit_value"`
	Used     int    `json:"used"`
	ResetsIn int    `json:"resets_in_seconds"`
}

func (r *refusal) Error() string {
	return fmt.Sprintf("%s: %s is %d for %s and %d is already spent; it resets in %ds",
		errThrottled, r.Limit, r.Value, r.Subject, r.Used, r.ResetsIn)
}

func (r *refusal) Unwrap() error { return errThrottled }

// retryAfter is the header 06 §4 requires alongside the body.
func (r *refusal) retryAfter() string { return strconv.Itoa(r.ResetsIn) }

// detail is the refusal as the error envelope carries it.
func (r *refusal) detail() map[string]any {
	return map[string]any{
		"limit": r.Limit, "subject": r.Subject, "limit_value": r.Value,
		"used": r.Used, "resets_in_seconds": r.ResetsIn,
	}
}

// bucket is one token bucket: `value` tokens that refill over `per`.
type bucket struct {
	tokens float64
	last   time.Time
}

// take refills by elapsed time and then spends n, reporting whether it could.
func (b *bucket) take(n float64, capacity float64, per time.Duration, now time.Time) bool {
	b.refill(capacity, per, now)
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func (b *bucket) refill(capacity float64, per time.Duration, now time.Time) {
	if b.last.IsZero() {
		b.tokens, b.last = capacity, now
		return
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(capacity, b.tokens+capacity*elapsed.Seconds()/per.Seconds())
		b.last = now
	}
}

// spend debits without refusing, for a cost that is only known afterwards. It
// is allowed to go negative: a single very large response should delay the next
// request in proportion, not be rounded away to nothing.
func (b *bucket) spend(n float64, capacity float64, per time.Duration, now time.Time) {
	b.refill(capacity, per, now)
	b.tokens -= n
}

// waitFor is how long until this bucket holds n tokens again.
func (b *bucket) waitFor(n, capacity float64, per time.Duration) time.Duration {
	if b.tokens >= n || capacity <= 0 {
		return 0
	}
	need := n - b.tokens
	return time.Duration(need / capacity * per.Seconds() * float64(time.Second))
}

// throttle is the gateway's in-process limiter.
//
// In memory, and deliberately. rpm and tpm are per-minute windows, so a restart
// costs at most one window's allowance — while keeping them in SQLite would put
// a write on every request, on the single writer connection that the audit
// chain, agent status and metering already share. daily_tokens is the exception
// and is read from the usage table, because a daily budget that a restart
// forgives is not a daily budget.
//
// ponytail: one mutex over every subject. Shard by subject if a dozen users
// ever becomes a thousand.
type throttle struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	inflight map[string]int
}

func newThrottle() *throttle {
	return &throttle{buckets: map[string]*bucket{}, inflight: map[string]int{}}
}

func (t *throttle) bucket(key string) *bucket {
	b, ok := t.buckets[key]
	if !ok {
		b = &bucket{}
		t.buckets[key] = b
	}
	return b
}

// admit decides whether one request may proceed.
//
// It returns a release that must always be called: it frees the concurrency
// slot and debits the tokens the response actually cost, which is the only
// moment tpm can be charged accurately.
func (t *throttle) admit(l limits, now time.Time, dailyUsed int) (release func(tokens int), ref *refusal) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Read-only checks first, so nothing has to be rolled back when one of
	// them refuses.
	//
	// Admission is decided on what is already spent, because a request's cost
	// does not exist until its response does — so a daily budget can be
	// exceeded by at most one request. At a budget of a million tokens that is
	// noise; there is no way to do better without refusing requests for tokens
	// they might not use.
	if l.daily.value > 0 && dailyUsed >= l.daily.value {
		return nil, &refusal{Limit: "daily_tokens", Subject: l.daily.subject,
			Value: l.daily.value, Used: dailyUsed, ResetsIn: secondsUntilDailyReset(now)}
	}
	if l.concurrent.value > 0 {
		key := "concurrent|" + l.concurrent.subject
		if used := t.inflight[key]; used >= l.concurrent.value {
			// Not time-based: a slot frees when a request finishes, and one
			// second is the shortest honest thing to tell a client.
			return nil, &refusal{Limit: "max_concurrent", Subject: l.concurrent.subject,
				Value: l.concurrent.value, Used: used, ResetsIn: 1}
		}
	}
	// tpm is charged after the fact, because the token count does not exist
	// until the response does. So the check is "is there anything left", and a
	// single huge response can leave the bucket empty for a while — which is
	// the behavior a tokens-per-minute ceiling should have.
	if l.tpm.value > 0 {
		b := t.bucket("tpm|" + l.tpm.subject)
		b.refill(float64(l.tpm.value), perMinute, now)
		if b.tokens < 1 {
			return nil, &refusal{Limit: "tpm", Subject: l.tpm.subject, Value: l.tpm.value,
				Used: l.tpm.value, ResetsIn: ceilSeconds(b.waitFor(1, float64(l.tpm.value), perMinute))}
		}
	}

	if l.rpm.value > 0 {
		b := t.bucket("rpm|" + l.rpm.subject)
		if !b.take(1, float64(l.rpm.value), perMinute, now) {
			return nil, &refusal{Limit: "rpm", Subject: l.rpm.subject, Value: l.rpm.value,
				Used: l.rpm.value, ResetsIn: ceilSeconds(b.waitFor(1, float64(l.rpm.value), perMinute))}
		}
	}

	concurrentKey := ""
	if l.concurrent.value > 0 {
		concurrentKey = "concurrent|" + l.concurrent.subject
		t.inflight[concurrentKey]++
	}

	return func(tokens int) {
		t.mu.Lock()
		defer t.mu.Unlock()
		if concurrentKey != "" {
			if t.inflight[concurrentKey]--; t.inflight[concurrentKey] <= 0 {
				delete(t.inflight, concurrentKey)
			}
		}
		if l.tpm.value > 0 && tokens > 0 {
			t.bucket("tpm|"+l.tpm.subject).spend(float64(tokens), float64(l.tpm.value), perMinute, time.Now())
		}
	}, nil
}

// dailyTokensUsed is what this user has spent since the last reset.
//
// From the usage table rather than from memory: a daily budget that a gateway
// restart forgives is not a budget, and the rows are already being written.
func (s *Server) dailyTokensUsed(ctx context.Context, userID string, now time.Time) (int, error) {
	var total sql.NullInt64
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT SUM(prompt_tokens + completion_tokens) FROM usage
		  WHERE user_id = ? AND ts >= ?`,
		userID, lastDailyReset(now).UTC().Format("2006-01-02T15:04:05.000Z")).Scan(&total)
	if err != nil {
		return 0, err
	}
	return int(total.Int64), nil
}

func lastDailyReset(now time.Time) time.Time {
	t := now.UTC()
	reset := time.Date(t.Year(), t.Month(), t.Day(), dailyResetHour, 0, 0, 0, time.UTC)
	if t.Before(reset) {
		reset = reset.AddDate(0, 0, -1)
	}
	return reset
}

func secondsUntilDailyReset(now time.Time) int {
	return ceilSeconds(lastDailyReset(now).AddDate(0, 0, 1).Sub(now.UTC()))
}

// ceilSeconds rounds up and never returns zero, because Retry-After: 0 invites
// a client straight back into the same refusal.
func ceilSeconds(d time.Duration) int {
	if s := int(math.Ceil(d.Seconds())); s > 0 {
		return s
	}
	return 1
}

// admit reads this caller's limits and asks the throttle to let one request
// through. A caller with no limits at all does no work beyond the one query.
func (s *Server) admit(ctx context.Context, p identity.Principal) (func(int), *refusal, error) {
	l, err := s.limitsFor(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	if l.none() {
		return func(int) {}, nil, nil
	}
	var dailyUsed int
	if l.daily.value > 0 {
		if dailyUsed, err = s.dailyTokensUsed(ctx, p.User.ID, s.now()); err != nil {
			return nil, nil, err
		}
	}
	release, ref := s.throttle.admit(l, s.now(), dailyUsed)
	if ref != nil {
		return func(int) {}, ref, nil
	}
	return release, nil, nil
}

// recordThrottled writes the refused request to usage.
//
// 06 §4 puts throttle events in usage and never in the audit chain: one is
// telemetry about how the system behaved, the other an administrative act with
// an accountable author. A refused request also carries no tokens — it never
// reached a model — so the row is the fact that it happened, and nothing else.
func (s *Server) recordThrottled(r *http.Request, p identity.Principal, model string, started time.Time) {
	err := observed.RecordUsage(r.Context(), s.db, observed.Usage{
		TS: started, UserID: p.User.ID, TokenID: p.Token.ID,
		Route: model, ModelID: model, RequestID: requestID(r),
		Status: http.StatusTooManyRequests, Latency: s.now().Sub(started),
	})
	if err != nil {
		s.log.Error("gateway", "detail", "recording a throttled request: "+err.Error(),
			"request_id", requestID(r))
	}
}
