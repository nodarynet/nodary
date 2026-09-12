package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/core"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// authorizeRead checks a read permission by name.
func authorizeRead(p identity.Principal, perm string) error {
	return identity.Authorize(p.Role, identity.Permission(perm))
}

func (s *Server) routes(mux *http.ServeMux) {
	h := func(method, path string, fn http.HandlerFunc) {
		mux.HandleFunc(method+" "+Prefix+path, fn)
	}

	// The node protocol. Enrollment is the only unauthenticated endpoint in the
	// product (docs/specs/03-agent.md §1); everything under /agent/ is mTLS.
	h("POST", "/enroll", s.enroll)
	h("GET", "/agent/desired", s.agentDesired)
	h("POST", "/agent/status", s.agentStatus)
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
	h("DELETE", "/users/{name}", s.deleteUser)
	h("GET", "/tokens", s.listTokens)
	h("POST", "/tokens", s.createToken)
	h("DELETE", "/tokens/{id}", s.revokeToken)

	// Audit, policy and config — R2-33.
	h("GET", "/audit", s.listAudit)
	h("GET", "/audit/verify", s.verifyAudit)
	h("GET", "/audit/export", s.exportAudit)
	h("GET", "/policy", s.showPolicy)
	h("GET", "/policy/diff", s.diffPolicy)
	h("POST", "/policy/apply", s.applyPolicy)
	h("GET", "/revisions", s.listRevisions)
	h("GET", "/revisions/{seq}", s.showRevision)
	h("POST", "/revisions/{seq}/rollback", s.rollback)
	h("GET", "/config/export", s.exportConfig)

	// Nodes — R2-26. Reads and the administrative transitions; enrollment and
	// verify-egress are the agent's, and arrive with R4.
	h("GET", "/nodes", s.listNodes)
	h("GET", "/nodes/{name}", s.showNode)
	h("POST", "/nodes/{name}/approve", s.nodeTransition("approve", "approved"))
	h("POST", "/nodes/{name}/drain", s.nodeTransition("drain", "draining"))

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
	h("GET", "/limits", s.listFleet("limits"))
	h("PUT", "/limits/{kind}/{id}", s.putLimit)
	h("POST", "/tokens/join", s.createJoinToken)
}

// --- auth --------------------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"username\":…,\"password\":…}"))
		return
	}

	// The verification is a mutation: a stale hash is rehashed on success, and
	// that write belongs in the same transaction as the login it authorized.
	var who identity.User
	rec, err := s.log.Act(r.Context(), audit.Request{
		Actor:  audit.Actor{ID: body.Username, Method: "password"},
		Action: "auth.login",
	}, func(m audit.Mutation) error {
		var err error
		who, err = identity.VerifyPassword(r.Context(), m, body.Username, body.Password)
		if err == nil {
			m.Detail("request_id", requestID(r))
		}
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	p := identity.Principal{User: who, Role: who.Role,
		Actor: audit.Actor{ID: who.ID, Method: "session"}}
	ttl := s.sessionTTL(r.Context())
	value := s.sessions.create(p, ttl, s.now())

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
		users, err := identity.List(r.Context(), d.DB.Read(), r.URL.Query().Get("all") == "true")
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, len(users))
		for i, u := range users {
			out[i] = map[string]any{"id": u.ID, "name": u.Name, "role": string(u.Role),
				"state": string(u.State), "totp_enrolled": u.TOTPEnrolled}
		}
		return map[string]any{"users": out}, nil
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name, Email, Role string }
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
		return map[string]any{"id": created.ID, "name": created.Name, "role": string(created.Role)}
	})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
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
			_, err := identity.Delete(r.Context(), m, p.Role, s.now(), name)
			return err
		},
	}, nil)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermTokenManage), func(d core.Deps) (any, error) {
		tokens, err := identity.ListTokens(r.Context(), d.DB.Read(), r.URL.Query().Get("user"))
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, len(tokens))
		for i, t := range tokens {
			// The display prefix, never a hash and never a secret
			// (docs/specs/10-cli.md §4).
			out[i] = map[string]any{"id": t.ID, "user_id": t.UserID, "kind": string(t.Kind),
				"prefix": t.Prefix, "revoked": t.Revoked(), "unattended": t.Unattended}
		}
		return map[string]any{"tokens": out}, nil
	})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User, Kind, Name string
		Unattended       bool
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
	var plaintext string
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
			if body.Unattended {
				active, _, err := policy.Active(r.Context(), s.db.Read())
				if err != nil {
					return err
				}
				if err := attest.AllowUnattendedMint(active); err != nil {
					return err
				}
			}
			_, plaintext, err = identity.MintToken(r.Context(), m, p.Role, s.now(),
				body.User, kind, body.Name, s.now().AddDate(0, 0, 90), body.Unattended)
			return err
		},
	}, func(core.Outcome) any {
		// Shown exactly once, at creation (10 §4). It is never readable again
		// and never appears in a listing.
		return map[string]any{"token": plaintext}
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
			_, err := identity.RevokeToken(r.Context(), m, p.Role, s.now(), id)
			return err
		},
	}, nil)
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
		records, err := audit.List(r.Context(), d.DB, f)
		if err != nil {
			return nil, err
		}
		return map[string]any{"records": records}, nil
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

func (s *Server) showPolicy(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		p, _, err := policy.Active(r.Context(), d.DB.Read())
		return p, err
	})
}

func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct{ Profile, Source string }
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
			return map[string]any{"from": from.Name, "to": candidate.Name, "changes": lines}, nil
		},
		Apply: func(m audit.Mutation, _ any) error {
			p, _ := s.principalOf(r)
			if err := policy.Apply(r.Context(), m, p.Role, s.now(), candidate, source); err != nil {
				return err
			}
			_, err := config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, nil)
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
		revs, err := config.List(r.Context(), d.DB.Read(), 50)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, len(revs))
		for i, rev := range revs {
			out[i] = map[string]any{"seq": rev.Seq, "ts": rev.TS.Format(audit.TimeFormat),
				"actor": rev.Actor, "justification": rev.Justification, "hash": rev.Hash}
		}
		return map[string]any{"revisions": out}, nil
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
		return map[string]any{"seq": rev.Seq, "actor": rev.Actor, "hash": rev.Hash,
			"snapshot": rev.Snapshot}, nil
	})
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		return config.Read(r.Context(), d.DB.Read())
	})
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
			p, _ := s.principalOf(r)
			if _, err := config.Apply(r.Context(), m, s.now(), target.Snapshot,
				config.Options{Prune: prune}); err != nil {
				return err
			}
			_, err := config.Record(r.Context(), m, s.now(), p.Actor.ID, r.Header.Get(HeaderJustify))
			return err
		},
	}, nil)
}

// --- fleet reads -------------------------------------------------------------

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
		// internal/fleet, not SQL here: `nodary node list` answers the same
		// question and this handler used to be the only implementation of it,
		// so the two could disagree about what a fleet looks like.
		nodes, err := fleet.Nodes(r.Context(), d.DB.Read(), s.now())
		return map[string]any{"nodes": nodes}, err
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
			// the record. That is docs/specs/02-enrollment.md §1's "neither side
			// can later claim terms the other did not see" made structural: the
			// terms are inside the hash the approver signed off, not in prose
			// beside it.
			Render: func(ctx context.Context, tx *sql.Tx) (any, error) {
				var from, offer, constraints string
				err := tx.QueryRowContext(ctx,
					`SELECT state, offer_json, constraints_json FROM node WHERE name = ?`, name).
					Scan(&from, &offer, &constraints)
				if err == sql.ErrNoRows {
					return nil, badRequest("no node named %q", name)
				}
				if err != nil {
					return nil, err
				}
				return map[string]any{"node": name, "from": from, "to": to,
					"offer": decodedJSON(offer), "constraints": decodedJSON(constraints)}, nil
			},
			Apply: func(m audit.Mutation, _ any) error {
				p, _ := s.principalOf(r)
				perm := identity.PermNodeApprove
				if verb == "drain" {
					perm = identity.PermNodeDrain
				}
				if err := identity.Authorize(p.Role, perm); err != nil {
					return err
				}
				stamped := s.now().UTC().Format(audit.TimeFormat)
				if to == "approved" {
					if _, err := m.Tx().ExecContext(r.Context(),
						`UPDATE node SET state = ?, approved_by = ?, approved_at = ? WHERE name = ?`,
						to, nullOrID(p), stamped, name); err != nil {
						return err
					}
				} else if _, err := m.Tx().ExecContext(r.Context(),
					`UPDATE node SET state = ? WHERE name = ?`, to, name); err != nil {
					return err
				}
				// `node.state` is in the configuration snapshot, so approving or
				// draining a node is a configuration change and records a
				// revision like every other one. Without this the revision chain
				// has a hole in it, and — since the agent long-poll compares
				// against that sequence — an approved node would not learn it
				// had been approved until something unrelated moved the
				// counter (docs/plans/R4a-agent-protocol.md §6).
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
			switch what {
			case "models":
				return map[string]any{"models": snap.Models}, nil
			case "deployments":
				return map[string]any{"deployments": snap.Deployments}, nil
			case "routes":
				return map[string]any{"routes": snap.Routes}, nil
			default:
				return map[string]any{"limits": snap.Limits}, nil
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

func nullOrID(p identity.Principal) any {
	if p.User.ID == "" {
		return nil
	}
	return p.User.ID
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

// showFleet is the single-object read for models, deployments and routes,
// served from the same snapshot the list endpoints use.
func (s *Server) showFleet(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.read(w, r, string(identity.PermStateRead), func(d core.Deps) (any, error) {
			snap, err := config.Read(r.Context(), d.DB.Read())
			if err != nil {
				return nil, err
			}
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
			// onto the fleet (docs/specs/02-enrollment.md §4).
			_, plaintext, err = identity.MintJoinToken(r.Context(), m, p.Role, s.now(),
				p.Actor.ID, body.Uses, s.now().Add(time.Hour))
			return err
		},
	}, func(core.Outcome) any { return map[string]any{"token": plaintext} })
}
