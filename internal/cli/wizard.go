package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/fleet"
)

// cmdInstall is the interactive route: one command, a handful of plain
// questions, and it drives the same verbs an operator would otherwise have to
// know to run in order — `server install`, `node approve`, `model register`,
// `user add`, `token create`. Nothing here is new capability; every step
// below is `cmdXxx(e, args)` for a verb that already exists, called the way a
// person at a terminal would call it themselves.
//
// **Why a wizard doesn't replace the flag-driven verbs.** A fleet grows past
// what one interactive session can drive — a second node, a scripted
// deployment, a CI pipeline — and those need arguments, not a conversation.
// This is the on-ramp, not the only ramp.
//
// **What it will not do, even here.** It never prompts for a password. The
// one-time setup link exists specifically so a password is never typed into a
// terminal, echoed in a log, or sitting in a config file
// (docs/specs/01-install.md §9) — a wizard that asked for one directly would
// quietly undo that. It prints the same link `server install` always did.
func cmdInstall(e env, args []string) int {
	fs := newFlagSet(e, "install")
	// Test-only, matching every install verb's own --root: stage into a
	// temporary tree instead of the real system paths, with nothing started
	// and no network reached. Not something a real run needs to know about.
	root := fs.String("root", "", "install into this prefix instead of / (for testing; nothing is started)")
	skipPreflight := fs.Bool("skip-preflight", false, "for testing")
	offline := fs.Bool("offline", false, "for testing")
	modelsDir := fs.String("models-dir", "", "where weights are staged, if not the default (rarely needed)")
	dbPath, keyPath := dbFlag(fs), keyFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !e.interactive() {
		fmt.Fprintf(e.stderr, "nodary install: this is an interactive wizard; run it at a terminal.\n"+
			"  A script uses `nodary server install` / `nodary node install` directly —\n"+
			"  see docs/specs/10-cli.md or https://nodarynet.github.io/nodary/getting-started/.\n")
		return ExitUsage
	}

	w := &wizard{e: e, root: *root, skipPreflight: *skipPreflight, offline: *offline,
		db: *dbPath, key: *keyPath, modelsDir: *modelsDir}

	fmt.Fprintln(e.stdout, "nodary — accountable GPU inference")
	fmt.Fprintln(e.stdout)

	switch w.choice("Is this machine the control plane, a GPU node joining one, or both?", []string{
		"Both — single box (recommended to start)",
		"Control plane only",
		"GPU node, joining a control plane elsewhere",
	}) {
	case 0:
		return w.server(true)
	case 1:
		return w.server(false)
	default:
		return w.nodeOnly()
	}
}

// wizard carries the one env and the test-only staging flags through every
// step, so each step reads like the question it's asking rather than a
// parameter list.
type wizard struct {
	e                      env
	root                   string
	skipPreflight, offline bool
	// db and key are test-only, mirroring every other verb's --db/--secret-key:
	// --root alone does not relocate the database (internal/paths keeps
	// nothing configurable, and openSession resolves --db independently of
	// it), so a test that stages one without the other would either write
	// into the real /var/lib/nodary or, running as the unprivileged user a
	// test runs as, simply fail there — see stagedInstall in litellm_test.go
	// for the precedent this follows.
	db, key string
	// modelsDir overrides where model() tells `model register` to look, for
	// an install that chose a non-default location — and, in a test, for
	// exactly the reason db/key are here.
	modelsDir string
}

// staged appends this wizard's test-only --root/--skip-preflight to a verb's
// argument list, for `server install` and `node install` — the two that take
// them. A real run has neither set, so it appends nothing.
func (w *wizard) staged(args []string) []string {
	if w.root != "" {
		args = append(args, "--root", w.root)
	}
	if w.skipPreflight {
		args = append(args, "--skip-preflight")
	}
	return args
}

// dbArgs is staged's counterpart for every verb after the install itself —
// approve, register, add, create — none of which take --root, and all of
// which need to be told where the staged database and its sealing key live,
// because --root alone does not relocate them (see the wizard struct's
// comment on db/key).
func (w *wizard) dbArgs(args []string) []string {
	if w.db != "" {
		args = append(args, "--db", w.db)
	}
	if w.key != "" {
		args = append(args, "--secret-key", w.key)
	}
	return args
}

func (w *wizard) server(withNode bool) int {
	host := w.string("Address other machines will reach this one at", "127.0.0.1")
	// server install is the one call that takes --root/--skip-preflight *and*
	// --db/--secret-key — node install takes only the first pair, which is why
	// these are two helpers rather than one.
	args := w.dbArgs(w.staged([]string{"--host", host}))
	if withNode {
		args = append(args, "--with-node")
	}
	if w.offline {
		args = append(args, "--offline")
	}
	if code := cmdServerInstall(w.e, args); code != ExitOK {
		return code
	}
	if !withNode {
		fmt.Fprintln(w.e.stderr,
			"\nControl plane installed. On each GPU host, run the `node install` command printed above.")
		return ExitOK
	}
	return w.afterEnroll()
}

func (w *wizard) nodeOnly() int {
	server := w.string("Control plane URL (https://host:8443)", "")
	token := w.string("Join token (from `nodary token join` on the control plane)", "")
	fingerprint := w.string("CA fingerprint (sha256:…, printed by `server install`)", "")
	for _, req := range []struct{ label, value string }{
		{"the control plane URL", server}, {"the join token", token}, {"the CA fingerprint", fingerprint},
	} {
		if req.value == "" {
			fmt.Fprintf(w.e.stderr, "nodary install: %s is required\n", req.label)
			return ExitUsage
		}
	}
	args := w.staged([]string{"--server", server, "--token", token, "--ca-fingerprint", fingerprint})
	if code := cmdNodeInstall(w.e, args); code != ExitOK {
		return code
	}
	return w.afterEnroll()
}

// afterEnroll is the two installs' shared tail: exactly one node is now
// pending, and everything from here — approve, stage, register, grant, key —
// is identical regardless of which install produced it.
func (w *wizard) afterEnroll() int {
	name, ok := w.pendingNode()
	if !ok {
		return ExitOK
	}
	if !w.yesNo("Approve "+name+" now?", true) {
		fmt.Fprintf(w.e.stderr, "\nRun `nodary node approve %s` when you're ready.\n", name)
		return ExitOK
	}
	approveArgs := w.dbArgs([]string{name, "--yes", "--justify", "approved during interactive install"})
	if code := cmdNodeTransition(w.e, approveArgs, "approve", "approved"); code != ExitOK {
		return code
	}

	if !w.yesNo("Stage and register a model now?", false) {
		fmt.Fprintf(w.e.stderr,
			"\nWhen you're ready: download weights (see the getting-started guide), then\n"+
				"  nodary model register <org/name> --node %s --gpu 0 --port 8001\n", name)
		return ExitOK
	}
	return w.model(name)
}

func (w *wizard) model(node string) int {
	repo := w.string("Model (HuggingFace org/name, weights already staged under the models directory)", "")
	if repo == "" {
		return ExitOK
	}
	gpu := w.string("GPU index", "0")
	port := w.string("Port", "8001")
	args := w.dbArgs([]string{repo, "--node", node, "--gpu", gpu, "--port", port,
		"--yes", "--justify", "registered during interactive install"})
	if w.modelsDir != "" {
		args = append(args, "--models-dir", w.modelsDir)
	}

	user := ""
	if w.yesNo("Create a user who can call it?", true) {
		user = w.string("  Name", "alice")
		role := w.string("  Role", "operator")
		userArgs := w.dbArgs([]string{user, "--role", role,
			"--yes", "--justify", "created during interactive install"})
		if code := cmdUserAdd(w.e, userArgs); code != ExitOK {
			return code
		}
		args = append(args, "--grant", user)
	}

	if code := cmdModelRegister(w.e, args); code != ExitOK {
		return code
	}

	if user != "" && w.yesNo("Mint "+user+" a service key now?", true) {
		tokenArgs := w.dbArgs([]string{"--user", user, "--kind", "sk",
			"--yes", "--justify", "minted during interactive install"})
		return cmdTokenCreate(w.e, tokenArgs)
	}
	return ExitOK
}

// pendingNode is the one node an install just enrolled.
//
// By name, not assumed: a control plane this wizard is joining may already
// have other nodes, pending or otherwise, and approving the wrong one is not
// a mistake this verb gets to make silently.
func (w *wizard) pendingNode() (string, bool) {
	path, _ := resolveDB(w.db)
	db, ok := openForReading(w.e, "install", path)
	if !ok {
		return "", false
	}
	defer db.Close()
	nodes, err := fleet.Nodes(context.Background(), db.Read(), time.Now())
	if err != nil {
		fmt.Fprintf(w.e.stderr, "nodary install: %v\n", err)
		return "", false
	}
	var pending []string
	for _, n := range nodes {
		if n.State == "pending" {
			pending = append(pending, n.Name)
		}
	}
	switch len(pending) {
	case 1:
		return pending[0], true
	case 0:
		fmt.Fprintln(w.e.stderr, "\nNo pending node found; `nodary node list` shows the fleet.")
	default:
		fmt.Fprintln(w.e.stderr,
			"\nMore than one node is pending; approve by name with `nodary node approve <name>`.")
	}
	return "", false
}

// --- prompting ---------------------------------------------------------------
//
// Three shapes, matching the three kinds of question this wizard asks: a free
// value with a sensible default, a yes/no, and a choice from a short list.
// Each reads one line through env.line(), the same shared buffered reader
// `attested`'s TOTP-and-confirm prompts use — a second bufio.Reader here would
// read ahead and find the next prompt's answer already consumed.

func (w *wizard) string(question, def string) string {
	if def != "" {
		fmt.Fprintf(w.e.stdout, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(w.e.stdout, "%s: ", question)
	}
	line, _ := w.e.line()
	if line == "" {
		return def
	}
	return line
}

func (w *wizard) yesNo(question string, defaultYes bool) bool {
	suffix := "[Y/n]"
	if !defaultYes {
		suffix = "[y/N]"
	}
	fmt.Fprintf(w.e.stdout, "%s %s ", question, suffix)
	line, _ := w.e.line()
	switch strings.ToLower(line) {
	case "":
		return defaultYes
	case "y", "yes":
		return true
	}
	return false
}

// choice reads a 1-based number and returns it 0-based. A blank answer or
// unreadable stdin defaults to the first option, which is worded as the
// recommended one for exactly this reason.
func (w *wizard) choice(question string, options []string) int {
	fmt.Fprintln(w.e.stdout, question)
	for i, o := range options {
		fmt.Fprintf(w.e.stdout, "  %d) %s\n", i+1, o)
	}
	for {
		fmt.Fprint(w.e.stdout, "> ")
		line, err := w.e.line()
		if line == "" {
			return 0
		}
		if n, convErr := strconv.Atoi(line); convErr == nil && n >= 1 && n <= len(options) {
			return n - 1
		}
		if err != nil {
			return 0
		}
		fmt.Fprintf(w.e.stdout, "  please enter a number from 1 to %d\n", len(options))
	}
}
