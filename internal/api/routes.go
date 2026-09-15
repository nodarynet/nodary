package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/backup"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/core"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/metering"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/policy"
)

// authorizeRead checks a read permission by name.
func authorizeRead(p identity.Principal, perm string) error {
	return identity.Authorize(p.Role, identity.Permission(perm))
}

// notIdempotent are the POSTs that Idempotency-Key does not wrap, each because
// it has no authenticated caller to scope a key to.
//
// An exemption list rather than wrapping the handlers that want it: a new POST
// added without a thought about replay is the failure this exists to prevent,
// so the default is on and a decision to leave it off is written down here.
var notIdempotent = map[string]string{
	// Runs before the credential it checks exists; a key would have nobody to
	// belong to. A replayed login is also harmless — it re-authenticates.
	"/auth/login":  "no principal yet",
	"/auth/logout": "ends the credential a key would be scoped to",
	// The agent protocol authenticates by client certificate and is already
	// idempotent by construction: the desired state is a complete end state and
	// a status post is an observation, not an act (dev/specs/03-agent.md §2).
	"/enroll":       "unauthenticated by design; a join token is single-use instead",
	"/agent/status": "an observation, replayed harmlessly",
	// A replayed batch is *not* harmless — it writes the chain twice — but the
	// wrapper cannot help: it scopes a key to a principal resolved from a
	// session or a bearer token, and this caller presents a client certificate.
	// Each event carries a node-minted id instead, so the two copies are
	// recognisable as one event (R4-10).
	"/agent/events": "no user principal to scope an idempotency key to",
	"/agent/renew":  "guarded by the certificate it replaces",
}

func (s *Server) routes(mux *http.ServeMux) {
	h := func(method, path string, fn http.HandlerFunc) {
		if method == http.MethodPost {
			if _, exempt := notIdempotent[path]; !exempt {
				fn = s.idempotent(fn)
			}
		}
		mux.HandleFunc(method+" "+Prefix+path, fn)
	}

	// The node protocol. Enrollment is the only unauthenticated endpoint in the
	// product (dev/specs/03-agent.md §1); everything under /agent/ is mTLS.
	h("POST", "/enroll", s.enroll)
	h("GET", "/agent/desired", s.agentDesired)
	h("POST", "/agent/status", s.agentStatus)
	h("POST", "/agent/events", s.agentEvents)
	h("POST", "/agent/renew", s.agentRenew)
	h("GET", "/agent/dist/{name}", s.serveDist)

	// The one address a person opens rather than a program calls, so it sits at
	// the root and not under Prefix. Unauthenticated, like enrollment, and for
	// the same reason: it runs before the credential it creates exists.
	mux.HandleFunc("GET "+SetupPath, s.setup)
	mux.HandleFunc("POST "+SetupPath, s.setup)

	// Auth — R2-25.
	h("POST", "/auth/login", s.login)
	h("POST", "/auth/logout", s.logout)
	h("GET", "/auth/whoami", s.whoami)

	// Users and tokens — R2-31.
	h("GET", "/users", s.listUsers)
	h("POST", "/users", s.createUser)
	h("PATCH", "/users/{name}", s.patchUser)
	h("DELETE", "/users/{name}", s.deleteUser)
	h("GET", "/tokens", s.listTokens)
	h("POST", "/tokens", s.createToken)
	h("DELETE", "/tokens/{id}", s.revokeToken)

	// Audit, policy and config — R2-33.
	h("GET", "/audit", s.listAudit)
	h("GET", "/audit/verify", s.verifyAudit)
	h("GET", "/audit/export", s.exportAudit)
	h("GET", "/backends", s.listBackends)
	h("GET", "/backends/{name}", s.showBackend)
	// R2-27. Registering and removing a backend are declarative and go through
	// config apply, which is one applier rather than a second set of writers —
	// the same reason `model register` has no POST /models. A build is not
	// declarative: it is an act with a result, so it has an endpoint.
	h("POST", "/backends/{name}/build", s.buildBackend)
	h("GET", "/backends/{name}/build", s.showBuild)
	h("GET", "/policy", s.showPolicy)
	h("GET", "/policy/diff", s.diffPolicy)
	h("POST", "/policy/apply", s.applyPolicy)
	h("GET", "/revisions", s.listRevisions)
	h("GET", "/revisions/{seq}", s.showRevision)
	h("POST", "/revisions/{seq}/rollback", s.rollback)
	h("GET", "/config/export", s.exportConfig)
	h("POST", "/backups", s.createBackup)
	h("GET", "/config/verify", s.verifyConfig)
	h("POST", "/config/apply", s.applyConfig)

	// Nodes — R2-26. Reads, the administrative transitions, and the stored
	// egress verdicts; enrollment is the agent's own path above.
	h("GET", "/nodes", s.listNodes)
	h("GET", "/nodes/{name}", s.showNode)
	h("POST", "/nodes/{name}/approve", s.nodeTransition("approve", "approved"))
	h("POST", "/nodes/{name}/drain", s.nodeTransition("drain", "draining"))
	h("POST", "/nodes/{name}/revoke", s.nodeTransition("revoke", "departed"))
	h("GET", "/nodes/{name}/verify-egress", s.verifyEgress)

	// Models, deployments and routes — R2-28, R2-29, R2-30. Reads now; their
	// mutations are declarative and go through config apply, which is one
	// applier rather than a second set of writers.
	h("GET", "/models", s.listFleet("models"))
	h("GET", "/models/{id}", s.showFleet("models"))
	h("GET", "/deployments", s.listFleet("deployments"))
	h("GET", "/deployments/{id}", s.showFleet("deployments"))
	h("GET", "/routes", s.listFleet("routes"))
	h("GET", "/routes/{name}", s.showFleet("routes"))
	h("PUT", "/routes/{name}", s.putRoute)
	h("POST", "/models/{id}/enable", s.modelToggle(false))
	h("POST", "/models/{id}/disable", s.modelToggle(true))
	h("POST", "/models/{id}/restart", s.modelRestart)
	h("POST", "/models/{id}/unstage", s.modelStageReset(fleet.Unstage))
	h("POST", "/models/{id}/restage", s.modelStageReset(fleet.Restage))
	h("GET", "/limits", s.listFleet("limits"))
	h("PUT", "/limits/{kind}/{id}", s.putLimit)
	h("POST", "/tokens/join", s.createJoinToken)

	// Usage — R2-32. The same reader `nodary usage show` uses.
	h("GET", "/usage", s.listUsage)
}

// --- auth --------------------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"username\":…,\"password\":…}"))
		return
	}

	now := s.now()
	keys := keysFor(body.Username, r)

	// Refused before anything expensive happens, and before anything is
	// written. That ordering is the point of both halves of this: no PBKDF2 for
	// an attacker to spend the control plane's only writer connection on, and
	// no audit row per attempt for them to grow the chain with.
	if wait := s.logins.lockedFor(keys, now); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(ceilSeconds(wait)))
		s.fail(w, r, fmt.Errorf("%w: too many failed attempts; try again in %s",
			errTooManyAttempts, wait.Round(time.Second)))
		return
	}
	s.logins.forget(now)

	// Outside any transaction. VerifyPassword says why at length: the hash is
	// the expensive part and the writer pool holds one connection.
	who, rehash, reason, err := identity.VerifyPassword(r.Context(), s.db.Read(),
		body.Username, body.Password)
	if err != nil {
		if engaged := s.logins.fail(keys, now); engaged {
			reason += "; further attempts locked out"
		}
		// Still audited, and still one row per attempt — but bounded now, at
		// five per key per window rather than as many as a network can carry.
		// The record gets the real reason; the caller gets "incorrect username
		// or password" and cannot tell an unknown account from a suspended one.
		_, _ = s.log.Act(r.Context(), audit.Request{
			Actor:  audit.Actor{ID: body.Username, Method: "password"},
			Action: "auth.login",
		}, func(m audit.Mutation) error {
			m.Detail("request_id", requestID(r))
			if reason != "" {
				m.Detail("reason", reason)
			}
			return err
		})
		s.fail(w, r, err)
		return
	}
	s.logins.succeed(body.Username)

	// The successful login and the hash upgrade it earned, in one transaction —
	// the property the old shape had and this one keeps. Only the arithmetic
	// moved out.
	rec, err := s.log.Act(r.Context(), audit.Request{
		Actor:  audit.Actor{ID: body.Username, Method: "password"},
		Action: "auth.login",
	}, func(m audit.Mutation) error {
		m.Detail("request_id", requestID(r))
		return rehash.Apply(r.Context(), m)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	ttl := s.sessionTTL(r.Context())
	value := s.sessions.create(who.ID, ttl, s.now())

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		Expires: s.now().Add(ttl),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user": who.Name, "role": string(who.Role),
		"expires_in_seconds": int(ttl.Seconds()), "audit_seq": rec.Seq,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	p, err := s.principalOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": p.User.Name, "role": string(p.Role), "method": p.Actor.Method,
		"unattended": p.Token.Unattended,
	})
}

// --- users and tokens --------------------------------------------------------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		p, err := readPage(r)
		if err != nil {
			return nil, err
		}
		users, err := identity.List(r.Context(), d.DB.Read(), r.URL.Query().Get("all") == "true")
		if err != nil {
			return nil, err
		}
		// Name and id, not name alone: `?all=true` can return a deleted user
		// and a live one sharing a name, and a cursor on the name by itself
		// would step over the second of them.
		users, next := paginate(users, p, func(u identity.User) string { return u.Name + "\x00" + u.ID })

		// **The email address is the one field this listing withholds**, and it
		// is withheld by role rather than by being left out of the shape.
		//
		// This endpoint is gated by PermStateRead, so every viewer in the fleet
		// can read it. 07 §1 gives a viewer "read state", and an account's
		// contact address is not fleet state — it is personal data attached to
		// a person, and a listing that hands every viewer every address is a
		// harvest rather than a read. User management is the admin's, so the
		// field travels with that permission. Nothing else is withheld: when an
		// account was created is the same kind of fact as its role.
		caller, _ := s.principalOf(r)
		manages := identity.Authorize(caller.Role, identity.PermUserManage) == nil

		out := make([]identity.UserReport, len(users))
		for i, u := range users {
			out[i] = identity.NewUserReport(u)
			if !manages {
				out[i].Email = ""
			}
		}
		return listBody("users", out, next), nil
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"name\":…,\"role\":…}"))
		return
	}
	role, err := identity.ParseRole(body.Role)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var created identity.User
	s.mutate(w, r, core.Change{
		Action: "user.add",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			taken := true
			if _, err := identity.Get(ctx, tx, body.Name); err != nil {
				taken = false
			}
			return map[string]any{"name": body.Name, "role": string(role),
				"email": body.Email, "name_taken": taken}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			var err error
			created, err = identity.Add(r.Context(), m, p.Role, s.now(), body.Name, body.Email, role)
			return err
		},
	}, func(core.Outcome) any {
		// The whole account, not three fields of it. The caller just created it
		// and supplied the address, so there is nothing here they do not
		// already have — and without the rest, `nodary user add --format json`
		// answers with a different document depending on which road it took.
		return identity.NewUserReport(created)
	})
}

// patchUser changes an account's state, which today means suspending it.
//
// 09 §1's `PATCH /users/{id}` with one thing to patch: the state machine in
// internal/identity is one-way — active to suspended or deleted, suspended to
// deleted — so there is no reinstatement to express, and a role change has no
// verb on either front end to be the counterpart of. Deletion keeps its own
// DELETE, because it is the irreversible one and should not be reachable by
// putting a different word in a body.
//
// Addressed by name rather than by id, as DELETE beside it already is: a name
// is what an operator types and what POST /tokens takes for the same account.
func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"state\":\"suspended\"}"))
		return
	}
	if body.State != string(identity.StateSuspended) {
		s.fail(w, r, badRequest(
			"state may only be set to %q here; deleting an account is DELETE /users/{name}",
			identity.StateSuspended))
		return
	}

	var after identity.User
	s.mutate(w, r, core.Change{
		Action: "user.suspend",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The state being moved *from* is read here, so suspending an
			// account somebody else already deleted refuses rather than
			// reporting a transition that never happened.
			before, err := identity.Get(ctx, tx, name)
			if err != nil {
				return nil, err
			}
			return map[string]any{"name": before.Name, "from": string(before.State),
				"to": string(identity.StateSuspended)}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			var err error
			after, err = identity.Suspend(r.Context(), m, p.Role, s.now(), name)
			return err
		},
	}, func(core.Outcome) any { return identity.NewUserReport(after) })
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var deleted identity.User
	s.mutate(w, r, core.Change{
		Action: "user.delete",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			before, err := identity.Get(ctx, tx, name)
			if err != nil {
				return nil, err
			}
			return map[string]any{"name": before.Name, "from": string(before.State), "to": "deleted"}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			var err error
			deleted, err = identity.Delete(r.Context(), m, p.Role, s.now(), name)
			return err
		},
	}, func(core.Outcome) any {
		return identity.NewUserReport(deleted)
	})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermTokenManage), func(d core.Deps) (any, error) {
		p, err := readPage(r)
		if err != nil {
			return nil, err
		}
		// `?user=` is the **name**, not the id: it is what an operator writes
		// and what `POST /tokens` already takes in its body. It used to be the
		// id, so the two endpoints disagreed about what a user is named by and
		// `?user=alice` silently matched nothing.
		userID := ""
		if name := r.URL.Query().Get("user"); name != "" {
			u, err := identity.Get(r.Context(), d.DB.Read(), name)
			if err != nil {
				return nil, err
			}
			userID = u.ID
		}
		tokens, err := identity.ListTokens(r.Context(), d.DB.Read(), userID)
		if err != nil {
			return nil, err
		}
		tokens, next := paginateDesc(tokens, p, func(t identity.Token) string {
			return t.CreatedAt.UTC().Format(audit.TimeFormat) + "\x00" + t.ID
		})

		// Join tokens belong to nobody, so filtering by user excludes them
		// rather than showing every enrollment credential to somebody who asked
		// about one account. The same rule `nodary token list` applies, because
		// this is the same listing.
		//
		// They are not paginated with the credentials: two sequences in one
		// body cannot share a cursor, and an outstanding join token is the
		// thing an operator is most often looking for here — losing it to a
		// page boundary would be the wrong one to lose.
		var joins []identity.JoinToken
		if userID == "" {
			if joins, err = identity.ListJoinTokens(r.Context(), d.DB.Read()); err != nil {
				return nil, err
			}
		}
		body := listBody("tokens", identity.TokenReports(tokens, s.now()), next)
		body["join_tokens"] = identity.JoinReports(joins)
		return body, nil
	})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User string `json:"user"`
		Kind string `json:"kind"`
		Name string `json:"name"`
		// Lifetime is the CLI's --expires: "90d", "12h", "never", or empty for
		// the per-kind default. It used to be absent and ninety days hardcoded,
		// which ignored what the caller asked for *and* what the profile
		// allows.
		Lifetime   string
		Unattended bool
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"user\":…,\"kind\":…}"))
		return
	}
	kind, err := identity.ParseKind(orDefault(body.Kind, "pt"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	expires, err := identity.ExpiryFor(kind, body.Lifetime, s.now())
	if err != nil {
		s.fail(w, r, badRequest("lifetime: %v", err))
		return
	}
	var plaintext string
	var minted identity.Token
	s.mutate(w, r, core.Change{
		Action: "token.create",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			u, err := identity.Get(ctx, tx, body.User)
			if err != nil {
				return nil, err
			}
			return map[string]any{"user": u.Name, "user_state": string(u.State),
				"kind": string(kind), "name": body.Name, "unattended": body.Unattended}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			// The profile bounds two things about a credential, and both are
			// decided here rather than at every later use: how long it may
			// live, and whether it may act with nobody present. The lifetime
			// check was on the CLI and not here, so a regulated install's
			// token_max_ttl_days bound one front end and not the other.
			active, _, err := policy.Active(r.Context(), s.db.Read())
			if err != nil {
				return err
			}
			if err := attest.AllowTokenLifetime(active, s.now(), expires); err != nil {
				return err
			}
			if body.Unattended {
				if err := attest.AllowUnattendedMint(active); err != nil {
					return err
				}
			}
			minted, plaintext, err = identity.MintToken(r.Context(), m, p.Role, s.now(),
				body.User, kind, body.Name, expires, body.Unattended)
			return err
		},
	}, func(core.Outcome) any {
		// The secret, shown exactly once at creation (10 §4): never readable
		// again and never in a listing. The credential's own description goes
		// with it, because `nodary token create` tells the operator its id and
		// when it expires — facts they cannot ask for afterwards by any means
		// that would identify *this* one out of several.
		return map[string]any{"token": plaintext,
			"credential": identity.NewTokenReport(minted, s.now())}
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var revoked identity.Token
	s.mutate(w, r, core.Change{
		Action: "token.revoke",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			before, err := identity.TokenByID(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			return map[string]any{"token": before.ID, "kind": string(before.Kind),
				"prefix": before.Prefix, "already_revoked": before.Revoked()}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			var err error
			revoked, err = identity.RevokeToken(r.Context(), m, p.Role, s.now(), id)
			return err
		},
	}, func(core.Outcome) any {
		return identity.NewTokenReport(revoked, s.now())
	})
}

// --- audit, policy, config ---------------------------------------------------

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		f := audit.Filter{Actor: r.URL.Query().Get("actor"), Action: r.URL.Query().Get("action")}
		var err error
		if f.From, err = audit.ParseBound(r.URL.Query().Get("from"), false); err != nil {
			return nil, err
		}
		if f.To, err = audit.ParseBound(r.URL.Query().Get("to"), true); err != nil {
			return nil, err
		}
		p, err := readPage(r)
		if err != nil {
			return nil, err
		}
		if f.BeforeSeq, err = p.seq(); err != nil {
			return nil, err
		}
		// One past the page, so "is there more" is answered by the same query
		// rather than by a second count that can disagree with it.
		f.Limit = p.limit + 1
		records, err := audit.List(r.Context(), d.DB, f)
		if err != nil {
			return nil, err
		}
		next := ""
		if len(records) > p.limit {
			records = records[:p.limit]
			next = strconv.FormatInt(records[len(records)-1].Seq, 10)
		}
		return listBody("records", records, next), nil
	})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		res, err := audit.VerifyDB(r.Context(), d.DB)
		if err != nil {
			return nil, err
		}
		body := map[string]any{"records": res.Records, "ok": res.OK()}
		if res.Break != nil {
			body["break"] = res.Break.String()
		}
		return body, nil
	})
}

// listBackends and showBackend are dev/specs/04-backends.md §9's reads.
//
// PermStateRead, like the policy: a descriptor holds no secret, and an operator
// deciding which backend to register a model against needs to see the argument
// vocabulary and the capabilities before they write `params`. The projection
// lives in internal/backend so that this and the CLI cannot drift.
func (s *Server) listBackends(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		reports, err := config.BackendReports(r.Context(), d.DB.Read())
		if err != nil {
			return nil, err
		}
		return map[string]any{"backends": reports}, nil
	})
}

func (s *Server) showBackend(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		rep, err := config.BackendReport(r.Context(), d.DB.Read(), r.PathValue("name"))
		if err != nil {
			// backend.ErrUnknown is in neither error table, so it would reach
			// a client as a 500 with the message withheld. Named as what it
			// is: the thing does not exist.
			return nil, fmt.Errorf("%w: %s", identity.ErrNotFound, err)
		}
		return rep, nil
	})
}

func (s *Server) showPolicy(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		p, _, err := policy.Active(r.Context(), d.DB.Read())
		return p, err
	})
}

func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Profile string `json:"profile"`
		Source  string `json:"source"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"profile\":…} or {\"source\":…}"))
		return
	}
	candidate, source, err := resolveProfile(body.Profile, body.Source)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.mutate(w, r, core.Change{
		Action: "policy.apply",
		Target: &audit.Target{Kind: "policy", ID: candidate.Name},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			from, _, err := policy.Active(ctx, tx)
			if err != nil {
				return nil, err
			}
			d := policy.Diff(from, candidate)
			lines := make([]string, len(d))
			for i, c := range d {
				lines[i] = c.String()
			}
			// The same preview the CLI renders, including what this profile
			// would deny that is already registered (R4-32). Two front ends
			// showing different previews of one act is the divergence the
			// tracker's first cross-cutting constraint exists to prevent —
			// and the half missing here is the one an operator needs to see
			// before agreeing.
			denied, err := config.Denied(ctx, tx, candidate)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"from": from.Name, "to": candidate.Name, "changes": lines}
			if len(denied) > 0 {
				out["denies"] = denied
			}
			return out, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
				return err
			}
			p, _ := s.principalOf(r)
			if err := policy.Apply(r.Context(), m, p.Role, s.now(), candidate, source); err != nil {
				return err
			}
			_, err := config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, func(out core.Outcome) any {
		// What the profile just applied refuses and is still serving, carried
		// back in the applied response rather than only in the preview.
		//
		// A caller that passed --yes never saw the preview, and the catalog
		// this is computed from is on this machine — so without it the only
		// way to learn what a policy change now denies is a second command
		// against a different endpoint. Flagged, not stopped, on both routes
		// (dev/specs/11-failure-modes.md).
		m, ok := out.Preview.(map[string]any)
		if !ok || m["denies"] == nil {
			return nil
		}
		return map[string]any{"denies": m["denies"]}
	})
}

// createBackup writes an archive on this host and leaves it here.
//
// **The archive never crosses the wire, and that is the design rather than a
// step that is missing.** dev/specs/08-data-model.md §4: it is as sensitive as
// /etc/nodary/secret.key because it contains it, together with the agent CA
// private key and the LiteLLM master key. Streaming it to whichever machine
// made the request would move this control plane's entire secret material onto
// one with a different security posture, as a side effect of a flag. What this
// endpoint buys is the attribution — an administrator can take a backup before
// a risky change without a shell here, and the chain says who did.
//
// `out` is therefore a path on *this* filesystem, and 08 §4's refusal is
// checked here, where the directory it names actually exists.
func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	// **Tagged, and ConfigDir is why.** encoding/json matches an untagged
	// field by name case-insensitively, which carries `out` to `Out` and
	// silently drops `config_dir` — the underscore is not a case difference.
	// The symptom was a backup that captured /etc/nodary on a host that has
	// no such directory, and the same shape once cost audit.Record its
	// prev_hash on the way back over the wire. Every field a client sends
	// gets a tag, not only the ones whose names have two words.
	var body struct {
		Out       string `json:"out"`
		ConfigDir string `json:"config_dir"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"out\":…}"))
		return
	}
	if body.Out == "" {
		s.fail(w, r, badRequest("out is required; it names the archive to write on this host"))
		return
	}
	if body.ConfigDir == "" {
		body.ConfigDir = paths.ConfigDir
	}
	if err := backup.CheckDestination(body.Out); err != nil {
		s.fail(w, r, err)
		return
	}

	s.mutate(w, r, core.Change{
		Action: "backup.create",
		Target: &audit.Target{Kind: "backup", ID: filepath.Base(body.Out)},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			return map[string]any{
				"out": body.Out, "database": s.db.Path(), "config_dir": body.ConfigDir,
				"includes_secret_key": true,
			}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			// Before the snapshot rather than after, so the record of the
			// backup is inside the backup.
			m.Detail("out", body.Out)
			m.Detail("config_dir", body.ConfigDir)
			return nil
		},
	}, func(core.Outcome) any {
		rep, err := backup.Create(r.Context(), s.db, s.now(), body.Out, body.ConfigDir)
		if err != nil {
			os.Remove(body.Out)
			return err
		}
		return rep
	})
}

func resolveProfile(name, source string) (policy.Profile, []byte, error) {
	if source != "" {
		p, err := policy.Parse([]byte(source))
		return p, []byte(source), err
	}
	if name == "" {
		return policy.Profile{}, nil, badRequest("name a built-in profile or supply a source")
	}
	return policy.Builtin(name)
}

func (s *Server) listRevisions(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		p, err := readPage(r)
		if err != nil {
			return nil, err
		}
		before, err := p.seq()
		if err != nil {
			return nil, err
		}
		revs, err := config.List(r.Context(), d.DB.Read(), p.limit+1, before)
		if err != nil {
			return nil, err
		}
		next := ""
		if len(revs) > p.limit {
			revs = revs[:p.limit]
			next = strconv.FormatInt(revs[len(revs)-1].Seq, 10)
		}
		return listBody("revisions", config.RevisionReports(revs), next), nil
	})
}

func (s *Server) showRevision(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
		if err != nil {
			return nil, badRequest("a revision is a number")
		}
		rev, err := config.Get(r.Context(), d.DB.Read(), seq)
		if err != nil {
			return nil, err
		}
		// The listing's fields and the snapshot, rather than three of the
		// first: `config show --rev` renders the configuration and the line
		// above it, and `ts` and `justification` were not in the answer at all.
		return map[string]any{"revision": config.NewRevisionReport(rev),
			"snapshot": rev.Snapshot}, nil
	})
}

// verifyConfig walks the revision chain, the way verifyAudit walks the audit
// chain.
//
// The walk belongs on the machine holding the revisions: every one carries a
// whole configuration snapshot, so verifying from outside would mean shipping
// the entire history to do arithmetic the control plane can do in place. It
// answers the same two things `nodary config verify` prints — how many
// verified, and what broke.
func (s *Server) verifyConfig(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		n, err := config.Verify(r.Context(), d.DB.Read())
		out := map[string]any{"revisions": n, "ok": err == nil}
		if err != nil {
			out["break"] = err.Error()
		}
		// A broken chain is a true answer, not a failed request: 200 with
		// ok:false, exactly as GET /audit/verify reports one.
		return out, nil
	})
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		return config.Read(r.Context(), d.DB.Read())
	})
}

// maxConfigDocument bounds an applied configuration. A whole fleet's TOML is
// kilobytes; anything near this is not one.
const maxConfigDocument = 4 << 20

// applyConfig applies a whole configuration document, which is what
// `nodary config apply -f FILE` sends over --server.
//
// **The body is the TOML, not a decoded snapshot**, and that is the decision
// worth writing down. [08 §2](../../dev/specs/08-data-model.md) makes the
// exported file and the applied file the same document, so the bytes an
// operator edited are what crosses the wire — and config.DecodeTOML runs once,
// on the machine that is about to apply them. A client that decoded first
// would be interpreting the document on one version of this code and applying
// it on another, and the preview would be rendered from its reading rather
// than from the control plane's.
//
// A document this control plane cannot read is therefore its refusal to make,
// and it is a 422 naming the line, not a 500.
func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigDocument))
	if err != nil {
		s.fail(w, r, badRequest("configuration document is larger than %d bytes", maxConfigDocument))
		return
	}
	want, err := config.DecodeTOML(body)
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: %v", config.ErrInvalid, err))
		return
	}
	prune := r.URL.Query().Get("prune") == "true"

	var result config.Result
	s.mutate(w, r, core.Change{
		Action: "config.apply",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// Rendered against live state, so an intent approved against one
			// configuration refuses to apply to another.
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"changes": config.FilterChanges(config.Changes(have, want), prune),
				"prune":   prune}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
				return err
			}
			p, _ := s.principalOf(r)
			var err error
			if result, err = config.Apply(r.Context(), m, s.now(), want,
				config.Options{Prune: prune}); err != nil {
				return err
			}
			_, err = config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, func(core.Outcome) any { return applyResult(result) })
}

// applyResult is what an apply did, so a client prints the same lines the CLI
// prints on the host — including the orphans, which are the ones an operator
// has to decide about.
func applyResult(r config.Result) map[string]any {
	changes, orphans := r.Changes, r.Orphans
	if changes == nil {
		changes = []string{}
	}
	if orphans == nil {
		orphans = []string{}
	}
	return map[string]any{"changes": changes, "orphans": orphans}
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil {
		s.fail(w, r, badRequest("a revision is a number"))
		return
	}
	target, err := config.Get(r.Context(), s.db.Read(), seq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	prune := r.URL.Query().Get("prune") == "true"
	var result config.Result
	s.mutate(w, r, core.Change{
		Action: "config.apply",
		Target: &audit.Target{Kind: "revision", ID: strconv.FormatInt(seq, 10)},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			return map[string]any{"changes": config.FilterChanges(config.Changes(have, target.Snapshot), prune), "prune": prune}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
				return err
			}
			p, _ := s.principalOf(r)
			var err error
			if result, err = config.Apply(r.Context(), m, s.now(), target.Snapshot,
				config.Options{Prune: prune}); err != nil {
				return err
			}
			_, err = config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, func(core.Outcome) any { return applyResult(result) })
}

// --- fleet reads -------------------------------------------------------------

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		// internal/fleet, not SQL here: `nodary node list` answers the same
		// question and this handler used to be the only implementation of it,
		// so the two could disagree about what a fleet looks like.
		p, err := readPage(r)
		if err != nil {
			return nil, err
		}
		nodes, err := fleet.Nodes(r.Context(), d.DB.Read(), s.now())
		if err != nil {
			return nil, err
		}
		items, next := paginate(nodes, p, func(n fleet.Node) string { return n.Name })
		return listBody("nodes", items, next), nil
	})
}

// nodeTransition is approve and drain: administrative decisions about a node
// that already exists. A node is never created here — it joins by enrolling.
func (s *Server) nodeTransition(verb, to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		s.mutate(w, r, core.Change{
			Action: "node." + verb,
			Target: &audit.Target{Kind: "node", ID: name},
			// The preview carries the node's advertised offer and constraints
			// because it is what the administrator is agreeing to, and because
			// core.Act hashes the preview into intent_hash and writes it into
			// the record. That is dev/specs/02-enrollment.md §1's "neither side
			// can later claim terms the other did not see" made structural: the
			// terms are inside the hash the approver signed off, not in prose
			// beside it.
			Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
				return fleet.TransitionPreview(ctx, tx, name, to)
			},
			Apply: func(m audit.Mutation, _ any) error {
				p, _ := s.principalOf(r)
				if err := identity.Authorize(p.Role, fleet.Permission(to)); err != nil {
					return err
				}
				if err := fleet.Transition(r.Context(), m, s.now(), name, to, p.User.ID); err != nil {
					return err
				}
				// `node.state` is in the configuration snapshot, so approving or
				// draining a node is a configuration change and records a
				// revision like every other one. Without this the revision chain
				// has a hole in it, and — since the agent long-poll compares
				// against that sequence — an approved node would not learn it
				// had been approved until something unrelated moved the
				// counter (dev/plans/R4a-agent-protocol.md §6).
				_, err := config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
				return err
			},
		}, nil)
	}
}

// listFleet serves the read half of models, deployments, routes and limits from
// the configuration snapshot, so the API and `config export` cannot describe
// the fleet differently.
func (s *Server) listFleet(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
			snap, err := config.Read(r.Context(), d.DB.Read())
			if err != nil {
				return nil, err
			}
			// What this read saw, so a client has something to send back as
			// If-Match (09 §2).
			setRevisionETag(r.Context(), w, d.DB.Read())
			p, err := readPage(r)
			if err != nil {
				return nil, err
			}
			// Each of these is already ordered by its own key in SQL, which is
			// what a keyed cursor needs and what config.Read guarantees.
			switch what {
			case "models":
				items, next := paginate(snap.Models, p, func(m config.Model) string { return m.ID })
				return listBody("models", items, next), nil
			case "deployments":
				items, next := paginate(snap.Deployments, p, func(d config.Deployment) string { return d.ID })
				return listBody("deployments", items, next), nil
			case "routes":
				items, next := paginate(snap.Routes, p, func(rt config.Route) string { return rt.Name })
				return listBody("routes", items, next), nil
			default:
				items, next := paginate(snap.Limits, p, func(l config.Limit) string {
					return l.SubjectKind + "/" + l.SubjectID
				})
				return listBody("limits", items, next), nil
			}
		})
	}
}

// decodedJSON turns a stored JSON column into ordinary Go values.
//
// A preview is hashed into intent_hash, and internal/canonical accepts a closed
// domain of Go types that json.RawMessage is deliberately not in: a preimage
// must be built from values the canonical encoder produced, or two identical
// documents that happened to be formatted differently would hash differently.
// Unparseable text is returned as itself, so a malformed column shows up in the
// preview rather than disappearing from it.
func decodedJSON(raw string) any {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// --- the remaining reads and the declarative PUTs ----------------------------

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	p, err := s.principalOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := authorizeRead(p, string(identity.PermStateRead)); err != nil {
		s.fail(w, r, err)
		return
	}
	format := orDefault(r.URL.Query().Get("format"), "jsonl")
	// The same encodings `audit export` writes, and not text or json: 09 §1
	// makes this flag an export encoding rather than a rendering style.
	if format != "jsonl" && format != "csv" {
		s.fail(w, r, badRequest("format must be jsonl or csv"))
		return
	}
	f := audit.Filter{Limit: audit.Unlimited}
	if f.From, err = audit.ParseBound(r.URL.Query().Get("from"), false); err != nil {
		s.fail(w, r, err)
		return
	}
	if f.To, err = audit.ParseBound(r.URL.Query().Get("to"), true); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		if _, err := audit.ExportCSV(r.Context(), s.db, f, w); err != nil {
			s.logf("audit export: %v", err)
		}
		return
	}
	if _, err := audit.ExportJSONL(r.Context(), s.db, f, w); err != nil {
		s.logf("audit export: %v", err)
	}
}

func (s *Server) diffPolicy(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		candidate, _, err := resolveProfile(r.URL.Query().Get("profile"), "")
		if err != nil {
			return nil, err
		}
		active, _, err := policy.Active(r.Context(), d.DB.Read())
		if err != nil {
			return nil, err
		}
		changes := policy.Diff(active, candidate)
		lines := make([]string, len(changes))
		for i, c := range changes {
			lines[i] = c.String()
		}
		return map[string]any{"active": active.Name, "candidate": candidate.Name,
			"changes": lines, "loosens": policy.Loosens(changes)}, nil
	})
}

func (s *Server) showNode(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		name := r.PathValue("name")
		detail, err := fleet.Show(r.Context(), d.DB.Read(), name, s.now())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: no node named %q", identity.ErrNotFound, name)
		}
		return detail, err
	})
}

// verifyEgress answers dev/specs/03-agent.md §5 for a whole node, from what
// the node last reported.
//
// A **read of a stored verdict, not a probe.** The assertion runs inside a
// deployment's network namespace on the machine hosting it (R4-29), which is
// somewhere the control plane cannot reach and must not try to — an endpoint
// that reached across the network to run it would have to hold a session open
// for three timeouts per deployment, and would answer "the node is
// unreachable" for the case an assessor most needs an answer to. The node
// probes after every start and reports what it found; this says what it said,
// and when.
//
// GET rather than POST for the same reason: nothing here acts.
func (s *Server) verifyEgress(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		name := r.PathValue("name")
		detail, err := fleet.Show(r.Context(), d.DB.Read(), name, s.now())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: no node named %q", identity.ErrNotFound, name)
		}
		if err != nil {
			return nil, err
		}
		out := []map[string]any{}
		for _, dep := range detail.Deployments {
			out = append(out, map[string]any{
				"deployment_id": dep.ID, "model_id": dep.ModelID,
				"state": dep.Egress, "reason": dep.EgressReason,
				"checked_at": dep.EgressCheckedAt,
			})
		}
		// last_seen travels with the verdicts deliberately: they are as fresh
		// as the node reporting them, and a stale node's compliant answer is
		// a statement about a machine nobody has heard from.
		return map[string]any{
			"node": detail.Name, "state": fleet.EgressState(detail.Deployments),
			"last_seen": detail.LastSeen, "stale": detail.Stale,
			"deployments": out,
		}, nil
	})
}

// showFleet is the single-object read for models, deployments and routes,
// served from the same snapshot the list endpoints use.
func (s *Server) showFleet(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
			snap, err := config.Read(r.Context(), d.DB.Read())
			if err != nil {
				return nil, err
			}
			setRevisionETag(r.Context(), w, d.DB.Read())
			switch what {
			case "models":
				for _, m := range snap.Models {
					if m.ID == r.PathValue("id") {
						return m, nil
					}
				}
			case "deployments":
				for _, dep := range snap.Deployments {
					if dep.ID == r.PathValue("id") {
						return dep, nil
					}
				}
			case "routes":
				for _, rt := range snap.Routes {
					if rt.Name == r.PathValue("name") {
						return rt, nil
					}
				}
			}
			return nil, fmt.Errorf("%w: no such %s", identity.ErrNotFound, strings.TrimSuffix(what, "s"))
		})
	}
}

// putRoute and putLimit are declarative writes, and they go through the same
// config applier every other configuration change uses rather than growing a
// second set of writers that could disagree with it.
func (s *Server) putRoute(w http.ResponseWriter, r *http.Request) {
	var body config.Route
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected a route object"))
		return
	}
	body.Name = r.PathValue("name")
	s.applyOne(w, r, "route."+body.Name, func(snap *config.Snapshot) {
		for i := range snap.Routes {
			if snap.Routes[i].Name == body.Name {
				snap.Routes[i] = body
				return
			}
		}
		snap.Routes = append(snap.Routes, body)
	})
}

func (s *Server) putLimit(w http.ResponseWriter, r *http.Request) {
	var body config.Limit
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected a limits object"))
		return
	}
	body.SubjectKind, body.SubjectID = r.PathValue("kind"), r.PathValue("id")
	s.applyOne(w, r, "limits."+body.SubjectKind, func(snap *config.Snapshot) {
		for i := range snap.Limits {
			if snap.Limits[i].SubjectKind == body.SubjectKind && snap.Limits[i].SubjectID == body.SubjectID {
				snap.Limits[i] = body
				return
			}
		}
		snap.Limits = append(snap.Limits, body)
	})
}

// applyOne edits the live configuration and applies it, so a single-object PUT
// is the same operation as a whole-file apply and records the same revision.
func (s *Server) applyOne(w http.ResponseWriter, r *http.Request, target string, edit func(*config.Snapshot)) {
	s.mutate(w, r, core.Change{
		Action: "config.apply",
		Target: &audit.Target{Kind: "config", ID: target},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			want, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			edit(want)
			return map[string]any{"changes": config.Changes(have, want)}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
				return err
			}
			p, _ := s.principalOf(r)
			want, err := config.Read(r.Context(), m.Tx())
			if err != nil {
				return err
			}
			edit(want)
			if _, err := config.Apply(r.Context(), m, s.now(), want, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, nil)
}

func (s *Server) createJoinToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Uses int    `json:"uses"`
		TTL  string `json:"ttl"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	if body.Uses <= 0 {
		body.Uses = 1
	}
	var plaintext string
	s.mutate(w, r, core.Change{
		Action: "token.join",
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			return map[string]any{"uses": body.Uses, "kind": "jt"}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			var err error
			// A join token must expire: one that never does is a permanent way
			// onto the fleet (dev/specs/02-enrollment.md §4).
			_, plaintext, err = identity.MintJoinToken(r.Context(), m, p.Role, s.now(),
				p.Actor.ID, body.Uses, s.now().Add(time.Hour))
			return err
		},
	}, func(core.Outcome) any { return map[string]any{"token": plaintext} })
}

// NotIdempotentForTest exposes the exemption list so a test can hold each entry
// to having a stated reason. Not part of the served surface.
func NotIdempotentForTest() map[string]string { return notIdempotent }

// modelToggle is R2-28's enable and disable: POST /models/{id}/enable and
// /disable, optionally narrowed with ?node=.
//
// The edit is config.SetDisabled, which `nodary model enable|disable` also
// calls, so the two front ends cannot disagree about which deployments a verb
// touches. What differs here is only what a front end knows: how the credential
// arrived and how to render the outcome.
//
// **Not applyOne**, which the route and limit PUTs use: those are declarative
// writes under config.apply's authority, and these are their own actions with
// their own permissions (dev/specs/07-identity-audit.md §1 names
// model.enable and model.disable). Recording a disable as `config.apply` would
// make the chain answer "who stopped this model" with the wrong verb.
func (s *Server) modelToggle(disabled bool) http.HandlerFunc {
	verb, perm := "enable", identity.PermModelEnable
	if disabled {
		verb, perm = "disable", identity.PermModelDisable
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		node := r.URL.Query().Get("node")
		edit := func(snap *config.Snapshot) int { return config.SetDisabled(snap, id, node, disabled) }

		s.mutate(w, r, core.Change{
			Action: "model." + verb,
			Target: &audit.Target{Kind: "model", ID: id},
			Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
				have, err := config.Read(ctx, tx)
				if err != nil {
					return nil, err
				}
				want, err := config.Read(ctx, tx)
				if err != nil {
					return nil, err
				}
				if edit(want) == 0 {
					return nil, notFound("%q has no deployment%s; GET /nodes names them", id, onNode(node))
				}
				return map[string]any{"changes": config.Changes(have, want), "node": node}, nil
			},
			Apply: func(m audit.Mutation, _ any) error {
				p, _ := s.principalOf(r)
				if err := identity.Authorize(p.Role, perm); err != nil {
					return err
				}
				if err := checkIfMatch(r.Context(), r, m.Tx()); err != nil {
					return err
				}
				want, err := config.Read(r.Context(), m.Tx())
				if err != nil {
					return err
				}
				edit(want)
				if _, err := config.Apply(r.Context(), m, s.now(), want, config.Options{}); err != nil {
					return err
				}
				_, err = config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
				return err
			},
		}, nil)
	}
}

func onNode(node string) string {
	if node == "" {
		return ""
	}
	return " on " + node
}

// modelRestart is R2-28's restart: POST /models/{id}/restart?node=NAME.
//
// **node is required, unlike enable and disable.** A restart is inherently a
// single node's act — cycling a systemd unit — where enable and disable are a
// fleet-wide declarative toggle. It is also edge-triggered rather than
// declarative: the params before and after a restart can be identical, so it
// writes its own table for the agent to consume and acknowledge, exactly as
// `nodary model restart` does through the same two fleet functions.
// modelRestart rolls a model's replicas: one at a time, never dropping the last
// that is serving (R4-22).
//
// `?node=` is **optional now**, and that is what makes this a roll. It used to
// be required on the reasoning that a restart is one node's act — true of
// cycling a unit, and not of the thing 03 §7 describes, which iterates over the
// replicas of a *model* and is the reason the guarantee exists at all. Named,
// it narrows the roll to one host's copies; omitted, it takes every replica in
// a fixed order.
// modelStageReset is `model unstage` and `model restage` over the network.
//
// Both preconditions and the write live in internal/fleet, so this handler
// decides nothing the CLI does not decide identically — it resolves the node
// from the query string and hands over. `?node=` is required here as it is
// there: without it the request names no node, and guessing one would discard
// weights on a machine nobody asked about.
func (s *Server) modelStageReset(verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		node := r.URL.Query().Get("node")
		if node == "" {
			s.fail(w, r, badRequest("?node= is required; it names whose copy this discards"))
			return
		}
		s.mutate(w, r, core.Change{
			Action: "model." + verb,
			Target: &audit.Target{Kind: "model", ID: id},
			Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
				return fleet.StageResetPreview(ctx, tx, verb, id, node)
			},
			Apply: func(m audit.Mutation, _ any) error {
				p, _ := s.principalOf(r)
				if err := identity.Authorize(p.Role, identity.PermModelStage); err != nil {
					return err
				}
				return fleet.RequestStageReset(r.Context(), m, s.now(), id, node)
			},
		}, nil)
	}
}

func (s *Server) modelRestart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node := r.URL.Query().Get("node")
	allowDowntime := r.URL.Query().Get("allow_downtime") == "true"

	var skipped []fleet.Replica
	s.mutate(w, r, core.Change{
		Action: "model.restart",
		Target: &audit.Target{Kind: "model", ID: id},
		Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			targets, disabled, err := fleet.RestartTargets(ctx, tx, id, node)
			if err != nil {
				return nil, err
			}
			if len(targets) == 0 && len(disabled) == 0 {
				return nil, notFound("%q has no deployment%s", id, onNode(node))
			}
			ready, err := fleet.ReadyReplicas(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			if err := fleet.AllowRoll(id, ready, len(targets), allowDowntime); err != nil {
				return nil, err
			}
			return map[string]any{"restart": fleet.ReplicaIDs(targets),
				"skipped_disabled": fleet.ReplicaIDs(disabled), "node": node,
				"ready_replicas": ready, "allow_downtime": allowDowntime}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			if err := identity.Authorize(p.Role, identity.PermModelRestart); err != nil {
				return err
			}
			// Re-derived rather than trusting the preview that round-tripped
			// through the response: apply runs in its own transaction and must
			// not depend on a value that only travelled through the screen —
			// and a replica that stopped serving in between changes the answer
			// to the downtime question.
			targets, disabled, err := fleet.RestartTargets(r.Context(), m.Tx(), id, node)
			if err != nil {
				return err
			}
			ready, err := fleet.ReadyReplicas(r.Context(), m.Tx(), id)
			if err != nil {
				return err
			}
			if err := fleet.AllowRoll(id, ready, len(targets), allowDowntime); err != nil {
				return err
			}
			skipped = disabled
			return fleet.RequestRestart(r.Context(), m, s.now(), fleet.RollID(s.now()), targets)
		},
	}, func(core.Outcome) any {
		if len(skipped) == 0 {
			return nil
		}
		// Named rather than silent: an operator who asked for a restart and got
		// one fewer than they have replicas needs to know which, and why.
		return map[string]any{"skipped_disabled": fleet.ReplicaIDs(skipped)}
	})
}

// listUsage is R2-32: GET /usage?from&to&user&model&node&group_by.
//
// Through internal/metering, which `nodary usage show` also calls, so the two
// front ends cannot report different totals for one question — and through
// audit.ParseBound for the dates, so `from=2026-09-01` means the same thing
// here as it does on `audit list`.
//
// **Every authenticated caller can read it, and that is the permission table as
// written rather than a choice made here.** dev/specs/07-identity-audit.md §1
// grants `usage.read.self` and `state.read` to the same role — RoleViewer, the
// lowest — so there is no line in it separating "my usage" from "everyone's",
// and nothing for this handler to enforce. Narrowing by role rank instead would
// put an access rule in a handler where the table cannot be read to find it,
// and inventing a `usage.read.all` would be vocabulary §1 does not define — the
// reasoning that kept PermRoute* from being invented for `route set`.
//
// So the gap is recorded against R2-32 rather than papered over: a site where a
// user should not see a colleague's token spend needs that permission to exist
// first. `nodary usage show` has the same reach today, for the same reason.
func (s *Server) listUsage(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, "", func(d core.Deps) (any, error) {
		p, err := s.principalOf(r)
		if err != nil {
			return nil, err
		}
		f := metering.Filter{
			User:  r.URL.Query().Get("user"),
			Model: r.URL.Query().Get("model"),
			Node:  r.URL.Query().Get("node"),
			Group: r.URL.Query().Get("group_by"),
		}
		if f.Group != "" && !metering.ValidGroup(f.Group) {
			return nil, badRequest("group_by must be user, model, node or route")
		}
		if f.From, err = audit.ParseBound(r.URL.Query().Get("from"), false); err != nil {
			return nil, err
		}
		if f.To, err = audit.ParseBound(r.URL.Query().Get("to"), true); err != nil {
			return nil, err
		}

		if err := authorizeRead(p, string(identity.PermUsageReadSelf)); err != nil {
			return nil, err
		}

		page, err := readPage(r)
		if err != nil {
			return nil, err
		}
		rows, err := metering.Query(r.Context(), d.DB.Read(), f)
		if err != nil {
			return nil, err
		}
		// **Paged only when ungrouped**, and that is not an omission. A grouped
		// report is ordered busiest-first, so a cursor keyed on the subject
		// would step over rows — and it is bounded anyway by how many distinct
		// users, models, nodes or routes exist, where the ungrouped listing has
		// one row per request and no bound at all. Truncating a report at 50
		// would also hide its tail while looking complete, which is the failure
		// a silent limit clamp is refused for elsewhere.
		if f.Group != "" {
			return listBody("usage", rows, ""), nil
		}
		items, next := paginate(rows, page, func(row metering.Row) string { return row.Subject })
		return listBody("usage", items, next), nil
	})
}
