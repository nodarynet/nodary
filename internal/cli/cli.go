// Package cli implements the nodary command surface.
//
// Output discipline (docs/specs/10-cli.md §4): human output goes to stdout,
// diagnostics and progress to stderr, and `--format json` emits a stable
// schema to stdout and nothing else.
package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Exit codes are the contract in docs/specs/10-cli.md §5.
const (
	ExitOK           = 0
	ExitFailure      = 1
	ExitUsage        = 2
	ExitAuth         = 3
	ExitPrecondition = 4
	ExitPolicy       = 5
	ExitUnreachable  = 6
)

// env carries the streams a command writes to, so every command is testable
// without touching os.Stdout.
type env struct {
	stdout io.Writer
	stderr io.Writer
}

// planned lists the verbs specified in docs/specs/10-cli.md that this release
// does not implement yet. They are recognised rather than rejected so the
// error says "not in this release" instead of "unknown command", which is the
// difference between a user waiting and a user filing a bug.
var planned = map[string]string{
	"server":    "control plane install and lifecycle",
	"node":      "GPU node install and fleet operations",
	"backend":   "backend descriptor registration",
	"model":     "catalog, staging and deployment",
	"route":     "public model routing",
	"user":      "user accounts",
	"token":     "token issue and revocation",
	"limits":    "rate and budget limits",
	"usage":     "usage reporting",
	"policy":    "policy profiles",
	"config":    "configuration revisions",
	"backup":    "backup and restore",
	"bundle":    "offline bundle creation",
	"upgrade":   "in-place upgrade",
	"uninstall": "uninstall",
	"doctor":    "diagnostics",
	"restart":   "restart local units",
	"status":    "local status",
}

// Main runs one invocation and returns its exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	e := env{stdout: stdout, stderr: stderr}

	if len(args) == 0 {
		usage(stdout)
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return ExitOK
	case "version", "--version", "-V":
		return cmdVersion(e, args[1:])
	case "components":
		return cmdComponents(e, args[1:])
	case "audit":
		return cmdAudit(e, args[1:])
	}

	if what, ok := planned[args[0]]; ok {
		fmt.Fprintf(stderr, "nodary %s: %s is not implemented in this release (%s)\n",
			args[0], what, versionString())
		fmt.Fprintf(stderr, "This release implements `version` and `components`. See docs/specs/10-cli.md.\n")
		return ExitFailure
	}

	fmt.Fprintf(stderr, "nodary: unknown command %q\n", args[0])
	fmt.Fprintf(stderr, "Run 'nodary help' for the command list.\n")
	return ExitUsage
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `nodary — accountable GPU inference, %s

Usage:
  nodary <command> [flags]

Available in this release:
  version              Print version and platform
  components           Inspect the pinned third-party component manifest
                         list    Show components this binary pins
                         verify  Check every pinned artifact resolves
  audit                Inspect the tamper-evident audit chain
                         list    Show records, newest first
                         verify  Walk the chain and report the first break
                         export  Write the chain as jsonl or csv

Specified, not yet implemented:
`, versionString())

	names := make([]string, 0, len(planned))
	for n := range planned {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-20s %s\n", n, planned[n])
	}

	fmt.Fprintf(w, `
Global flags:
  --format text|json   Output format; json is stable and intended for scripting

Documentation: docs/specs/
`)
}

// formatFlag registers the shared --format flag.
func formatFlag(fs *flag.FlagSet) *string {
	return fs.String("format", "text", "output format: text|json")
}

func checkFormat(e env, format string) bool {
	switch format {
	case "text", "json":
		return true
	}
	fmt.Fprintf(e.stderr, "nodary: unknown --format %q (want text or json)\n", format)
	return false
}

// newFlagSet builds a FlagSet that reports errors through our own streams and
// never calls os.Exit, so Main stays the single place an exit code is decided.
func newFlagSet(e env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

func versionString() string {
	return strings.TrimSpace(buildVersion())
}
