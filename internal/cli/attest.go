package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// ceremonyFlags are the global flags of docs/specs/10-cli.md §2 that every
// mutating verb carries.
type ceremonyFlags struct {
	justify *string
	totp    *string
	yes     *bool
	dryRun  *bool
}

func attestFlags(fs *flag.FlagSet) ceremonyFlags {
	return ceremonyFlags{
		justify: justifyFlag(fs),
		totp:    fs.String("totp", "", "TOTP code, when the active profile requires re-authentication"),
		yes:     fs.Bool("yes", false, "skip the confirmation; does not skip justification or TOTP"),
		dryRun:  fs.Bool("dry-run", false, "render the change and its intent hash; apply nothing"),
	}
}

// change is one mutation, described well enough to attest to.
type change struct {
	action string
	target *audit.Target
	// render produces the preview. It runs twice — once to show and hash, once
	// inside the transaction to bind — so it must read state rather than echo
	// arguments, or it hashes something that cannot move.
	render attest.Render
	// apply performs the change. The bound preview is passed back so a verb
	// need not re-read what the render already resolved.
	apply func(m audit.Mutation, bound any) error
}

// attested runs the whole of docs/specs/07-identity-audit.md §2 and then the
// act: preview, hash, ceremony, confirmation, and the re-render that binds the
// approved preview to what is applied.
//
// One function, because the alternative is each verb deciding for itself how
// much ceremony to demand, and the first one to get it wrong is the one nobody
// reviews.
// The bool reports whether the change was actually applied. A --dry-run and a
// declined confirmation both return false with a zero record, and a caller that
// ignored it would print a result for something that never happened.
func (s *session) attested(e env, verb string, c change, f ceremonyFlags, format string) (audit.Record, bool, int) {
	ctx := context.Background()

	active, _, err := policy.Active(ctx, s.db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return audit.Record{}, false, ExitFailure
	}

	// The preview runs against a read snapshot. Its hash is what the operator
	// approves and what Bind compares against inside the transaction.
	preview, err := s.preview(ctx, c.render)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return audit.Record{}, false, exitFor(err)
	}
	intent, err := attest.Hash(preview)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return audit.Record{}, false, ExitFailure
	}

	// --dry-run stops before ceremony: there is nothing to justify because
	// nothing will happen.
	if *f.dryRun {
		return audit.Record{}, false, writeDryRun(e, verb, format, c.action, intent, preview)
	}

	cer := attest.Ceremony{
		Justification: *f.justify,
		TOTPCode:      *f.totp,
		Unattended:    s.who.Token.Unattended,
		Local:         s.who.Local(),
		Interactive:   e.interactive(),
	}
	if err := attest.Require(active, cer); err != nil {
		// A missing code is the one refusal a human can still satisfy here.
		if errors.Is(err, attest.ErrTOTPRequired) && cer.Interactive {
			if cer.TOTPCode, err = promptTOTP(e); err != nil {
				fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
				return audit.Record{}, false, ExitPolicy
			}
		} else {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return audit.Record{}, false, ExitPolicy
		}
	}

	// --yes skips this and only this. docs/specs/10-cli.md §2 is explicit that
	// it skips neither justification nor TOTP, and both are already settled.
	if !*f.yes && cer.Interactive {
		showPreview(e, c.action, intent, preview)
		if !confirm(e) {
			fmt.Fprintf(e.stderr, "nodary %s: cancelled; nothing was applied\n", verb)
			return audit.Record{}, false, ExitCancelled
		}
	}

	req := s.request(c.action, c.target, cer.Justification)
	req.IntentHash = intent

	rec, err := s.log.Act(ctx, req, func(m audit.Mutation) error {
		if err := s.touch(m); err != nil {
			return err
		}
		// Re-authentication is spent inside the act it authorises, so a code and
		// the change it attests to commit together or not at all.
		// Recorded rather than silent: under a profile that requires
		// re-authentication, an act that did not carry one has to say why.
		if active.RequireTOTP && !attest.NeedsTOTP(active, cer) {
			if cer.Local {
				m.Detail("totp_exempt", "local")
			} else {
				m.Detail("totp_exempt", "unattended")
			}
		}
		if attest.NeedsTOTP(active, cer) {
			k, err := s.key()
			if err != nil {
				return err
			}
			if _, err := identity.VerifyTOTP(ctx, m, s.now, k, s.who.User.Name, cer.TOTPCode); err != nil {
				return err
			}
		}
		bound, err := attest.Bind(ctx, m.Tx(), c.render, intent)
		if err != nil {
			return err
		}
		return c.apply(m, bound)
	})
	if err != nil {
		return rec, false, reportActFailure(e, verb, rec, err)
	}
	return rec, true, ExitOK
}

// preview runs a render outside any mutation, in a transaction it rolls back.
//
// A read-only connection would be simpler and would not do: a render sees the
// same snapshot semantics as the apply path only if it runs in a transaction,
// and a preview that read differently from the bind would refuse changes that
// had not moved.
func (s *session) preview(ctx context.Context, r attest.Render) (any, error) {
	tx, err := s.db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("opening a preview transaction: %w", err)
	}
	defer tx.Rollback()
	return r(ctx, tx)
}

func showPreview(e env, action, intent string, preview any) {
	fmt.Fprintf(e.stderr, "%s\n", action)
	for _, l := range describe(preview) {
		fmt.Fprintf(e.stderr, "  %s\n", l)
	}
	fmt.Fprintf(e.stderr, "intent %s\n", intent)
}

// writeDryRun prints the change and its hash and applies nothing.
//
// The preview goes to stderr everywhere else, because docs/specs/10-cli.md §4
// reserves stdout for a stable schema. Here the preview *is* the output, so
// under --format json it is the JSON document on stdout.
func writeDryRun(e env, verb, format, action, intent string, preview any) int {
	if format == "json" {
		return writeJSON(e, verb, map[string]any{
			"dry_run": true, "action": action, "intent_hash": intent, "change": preview,
		})
	}
	fmt.Fprintf(e.stdout, "%s\n", action)
	for _, l := range describe(preview) {
		fmt.Fprintf(e.stdout, "  %s\n", l)
	}
	fmt.Fprintf(e.stdout, "intent %s\n", intent)
	fmt.Fprintf(e.stderr, "dry run: nothing was applied\n")
	return ExitOK
}

// describe renders a preview for a human by walking its JSON form, so a verb
// describes its change by returning data rather than by formatting strings.
func describe(preview any) []string {
	raw, err := json.Marshal(preview)
	if err != nil {
		return []string{fmt.Sprint(preview)}
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return []string{string(raw)}
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%-20s %v", k, fields[k]))
	}
	return out
}

func promptTOTP(e env) (string, error) {
	fmt.Fprintf(e.stderr, "policy requires re-authentication for this act.\nTOTP code: ")
	line, err := e.line()
	if err != nil && line == "" {
		return "", fmt.Errorf("%w: no code was entered", attest.ErrTOTPRequired)
	}
	return line, nil
}

func confirm(e env) bool {
	fmt.Fprintf(e.stderr, "apply? [y/N] ")
	line, _ := e.line()
	switch strings.ToLower(line) {
	case "y", "yes":
		return true
	}
	return false
}
