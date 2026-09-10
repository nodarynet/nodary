package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"

	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/scripts"
)

// invokingUser is the human at the keyboard, for suggesting a sensible
// default username when the wizard creates one — not the audit actor
// (identity.LocalRoot / localPrincipal in session.go), which stays "root"
// deliberately: that is who is really acting, sudo or not. $SUDO_USER is
// what sudo sets to the original login; user.Current() covers running the
// wizard as root directly, with no sudo in the picture at all.
func invokingUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// streamCommand runs name with args, live: stdout/stderr go straight to the
// caller's rather than being buffered and printed at the end. A multi-gigabyte
// download is minutes to hours, and install.Runner's CombinedOutput() would
// leave the wizard silent for all of it — this is that function's shape,
// for the one step here too long to buffer.
type streamCommand func(ctx context.Context, stdout, stderr io.Writer, env []string, name string, args ...string) error

func execStreaming(ctx context.Context, stdout, stderr io.Writer, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if env != nil {
		cmd.Env = env
	}
	return cmd.Run()
}

// fetchWeights runs stage-model.sh's exact, already-verified download and
// manifest logic — embedded as scripts.StageModelSH rather than reimplemented
// in Go, so there is one implementation of "list a repo's files, fetch them,
// hash them" and not two — as the account that invoked sudo, straight into
// dir. Doing this here, instead of sending the operator off to run it first,
// is the whole reason this exists: type a repo, and the only other question
// is whether it needs a token.
//
// **It never runs the download as root.** `usermod`/`install -d` are the
// only privileged steps, and neither touches the network; both are exactly
// what getting-started.md's manual group-grant asks an operator to run by
// hand, automated rather than replaced. runuser then drops to the invoking
// user for the fetch itself — a fresh process, so unlike a shell the operator
// is already sitting in, it sees that new group membership immediately, with
// no `newgrp` or re-login needed.
func (w *wizard) fetchWeights(repo, dir string) bool {
	who := invokingUser()
	if who == "" || who == "root" {
		fmt.Fprintln(w.e.stderr,
			"nodary install: no unprivileged account to download as (not run through sudo) — "+
				"place weights yourself (see the getting-started guide) and choose "+
				"\"already staged\" instead.")
		return false
	}

	run := w.runCmd
	if run == nil {
		run = install.Exec
	}
	if out, err := run(context.Background(), "usermod", "-aG", "nodary", who); err != nil {
		fmt.Fprintf(w.e.stderr, "nodary install: granting %s access to stage weights: %v\n%s\n", who, err, out)
		return false
	}
	if out, err := run(context.Background(), "install", "-d", "-o", who, "-g", "nodary", "-m", "2750", dir); err != nil {
		fmt.Fprintf(w.e.stderr, "nodary install: preparing %s: %v\n%s\n", dir, err, out)
		return false
	}

	token := w.string(
		"HuggingFace token (only for a gated repository — Gemma, Llama, Mistral — leave blank otherwise)", "")

	f, err := os.CreateTemp("", "nodary-stage-*.sh")
	if err != nil {
		fmt.Fprintf(w.e.stderr, "nodary install: %v\n", err)
		return false
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(scripts.StageModelSH)
	closeErr := f.Close()
	// World-readable and executable: it holds no secret (it is the public
	// script getting-started.md already tells an operator to curl), and the
	// account runuser drops to next has to be able to read and run it.
	chmodErr := os.Chmod(f.Name(), 0o755)
	if writeErr != nil || closeErr != nil || chmodErr != nil {
		fmt.Fprintf(w.e.stderr, "nodary install: writing the download helper: %v\n", firstNonNil(writeErr, closeErr, chmodErr))
		return false
	}

	var env []string
	if token != "" {
		// On the environment, never argv: a token passed as a command-line
		// argument sits in the process table (`ps aux`) for anyone on the
		// box to read for as long as the download runs. --preserve-environment
		// is explicit about carrying it through; runuser's own default
		// already does, but this is not the place to rely on a default.
		env = append(os.Environ(), "HF_TOKEN="+token)
	}
	args := []string{"--preserve-environment", "-u", who, "--", "bash", f.Name(), repo, "--models-dir", dir}

	stream := w.download
	if stream == nil {
		stream = execStreaming
	}
	fmt.Fprintln(w.e.stderr)
	if err := stream(context.Background(), w.e.stdout, w.e.stderr, env, "runuser", args...); err != nil {
		fmt.Fprintf(w.e.stderr, "\nnodary install: %v\n", err)
		return false
	}
	return true
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
