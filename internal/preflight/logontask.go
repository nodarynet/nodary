package preflight

import (
	"context"
	"encoding/csv"
	"io"
	"os/exec"
	"strings"
)

// What a WSL2 node can say about being brought back after a Windows reboot.
//
// dev/specs/01-install.md §8: the distribution does not start at boot, so a
// rebooted Windows host comes back with no agent unless a scheduled task starts
// it at logon. dev/specs/11-failure-modes.md §2 makes that a node going `stale`
// like any unreachable host — which is the right *behaviour* and a terrible
// diagnosis, because nothing about a stale node says the machine is fine and
// simply never started the distribution.
const (
	// LogonTaskNotWSL is the empty answer: this is not a WSL2 host and the
	// question does not arise. Distinct from Unknown, which is a WSL2 host
	// that could not be asked — one is "not applicable" and the other is
	// "nobody knows", and showing them alike would be a warning that never
	// fires or one that always does.
	LogonTaskNotWSL   = ""
	LogonTaskPresent  = "present"
	LogonTaskAbsent   = "absent"
	LogonTaskUnknown  = "unknown"
	logonTaskFallback = "/mnt/c/Windows/System32/schtasks.exe"
)

// WSLLogonTask asks Windows whether anything starts this distribution at logon.
//
// **It asks Windows, because only Windows knows.** The task lives in the host's
// scheduler, not in the distribution, so there is nothing inside Linux to read
// — and WSL's interop makes the Windows binary runnable from here, which is the
// one channel that exists.
func WSLLogonTask(ctx context.Context) string {
	if !IsWSL() {
		return LogonTaskNotWSL
	}
	bin, err := exec.LookPath("schtasks.exe")
	if err != nil {
		bin = logonTaskFallback
	}
	out, err := exec.CommandContext(ctx, bin, "/query", "/fo", "csv", "/v").Output()
	if err != nil {
		// Interop can be turned off, and a host can refuse the query. Neither
		// is evidence that no task exists.
		return LogonTaskUnknown
	}
	return parseLogonTasks(strings.NewReader(string(out)))
}

// parseLogonTasks reads schtasks' own CSV, apart from running it so a test can
// hand it what a real host printed.
//
// **Columns are found by their heading, never by position.** schtasks prints
// more than thirty of them, the set moves between Windows releases, and it
// repeats the header row for each section — so a parser that counted would read
// a schedule type as a command on the next release, and would count the header
// itself as a task.
func parseLogonTasks(r io.Reader) string {
	rd := csv.NewReader(r)
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil || len(rows) == 0 {
		return LogonTaskUnknown
	}
	command, schedule := -1, -1
	for i, h := range rows[0] {
		switch strings.TrimSpace(h) {
		case "Task To Run":
			command = i
		case "Schedule Type":
			schedule = i
		}
	}
	if command < 0 || schedule < 0 {
		return LogonTaskUnknown
	}
	for _, row := range rows[1:] {
		if len(row) <= command || len(row) <= schedule {
			continue
		}
		// The header repeats through the output; it is not a task.
		if strings.TrimSpace(row[command]) == "Task To Run" {
			continue
		}
		// "At logon time" is the vocabulary, read off a real host rather than
		// recalled. Matched loosely because it is a localized string and an
		// exact compare would answer `absent` on every non-English Windows —
		// which is the direction that strands a machine silently.
		if !strings.Contains(strings.ToLower(row[schedule]), "logon") {
			continue
		}
		if strings.Contains(strings.ToLower(row[command]), "wsl") {
			return LogonTaskPresent
		}
	}
	return LogonTaskAbsent
}

// checkWSLLogonTask is R5-04's warning about a node that will not come back.
//
// A warning and never a failure: 01 §11 keeps these out of the way of an
// install, and a machine somebody is about to log into anyway is perfectly
// usable without one. What it buys is the diagnosis — 11 §2 makes a Windows
// host rebooted without a logon task look exactly like any other stale node,
// and "the distribution never started" is fixed in thirty seconds by somebody
// who knows that is what happened.
// logonTask is the query, as a variable so the package's own tests do not each
// spend two seconds on Windows interop. Run() is called seven times across
// them and a real `schtasks /query /v` takes about that long, which turned a
// 0.2s package into a 30s one — a cost every `make check` would pay for a fact
// no test here is about.
var logonTask = WSLLogonTask

func checkWSLLogonTask(ctx context.Context) Check {
	c := Check{Name: "wsl logon task", Level: LevelSkip}
	switch logonTask(ctx) {
	case LogonTaskNotWSL:
		c.Detail = "not a WSL2 host"
	case LogonTaskPresent:
		c.Level, c.Detail = LevelOK, "a scheduled task starts this distribution at logon"
	case LogonTaskAbsent:
		c.Level = LevelWarn
		c.Detail = "no scheduled task starts this distribution at logon, so a Windows reboot\n" +
			"    leaves this node stale until somebody opens a shell. Create one that runs\n" +
			"    `wsl.exe -d <distribution>` at logon (dev/specs/01-install.md §8)."
	default:
		c.Level = LevelWarn
		c.Detail = "Windows could not be asked whether a logon task exists; interop may be off"
	}
	return c
}
