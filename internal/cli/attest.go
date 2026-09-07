package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/core"
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
	ch := core.Change{Action: c.action, Target: c.target, Render: c.render, Apply: c.apply}

	// Rendered once here so the operator can be shown what they are approving,
	// and the hash is then passed back as the intent: what gets applied is what
	// was on the screen, bound rather than assumed.
	shown, intent, err := core.Preview(ctx, s.deps(), ch)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return audit.Record{}, false, exitFor(err)
	}
	if *f.dryRun {
		return audit.Record{}, false, writeDryRun(e, verb, format, c.action, intent, shown)
	}

	// --yes skips this and only this. docs/specs/10-cli.md §2 is explicit that
	// it skips neither justification nor TOTP, and neither is decided here.
	if !*f.yes && e.interactive() {
		showPreview(e, c.action, intent, shown)
		if !confirm(e) {
			fmt.Fprintf(e.stderr, "nodary %s: cancelled; nothing was applied\n", verb)
			return audit.Record{}, false, ExitCancelled
		}
	}

	req := core.Request{
		Principal: s.who,
		Ceremony: attest.Ceremony{
			Justification: *f.justify,
			TOTPCode:      *f.totp,
			Interactive:   e.interactive(),
		},
		Intent: intent,
	}

	out, err := core.Act(ctx, s.deps(), req, ch)
	// A missing code is the one refusal a human can still satisfy, and asking
	// is the CLI's job: core.Act cannot prompt and an HTTP handler has nobody
	// to prompt, so it reports what is missing and each front end answers in
	// its own way.
	if errors.Is(err, core.ErrTOTPRequired) && req.Ceremony.Interactive {
		code, perr := promptTOTP(e)
		if perr != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, perr)
			return audit.Record{}, false, ExitPolicy
		}
		req.Ceremony.TOTPCode = code
		out, err = core.Act(ctx, s.deps(), req, ch)
	}
	if err != nil {
		if core.IsPolicyRefusal(err) {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return out.Record, false, ExitPolicy
		}
		return out.Record, false, reportActFailure(e, verb, out.Record, err)
	}
	return out.Record, true, ExitOK
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
