package preflight

import (
	"strings"
	"testing"
)

// Read off a real Windows host: the header repeats through the output, the
// column set is wide, and "At logon time" is the vocabulary.
const schtasksCSV = `"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time"
"DESKTOP","\Adobe Acrobat Update Task","9/15/2026 7:00:00 AM","Ready","Interactive/Background","9/14/2026","0","Adobe","C:\Program Files\Adobe\AcrobatUpdater.exe","N/A","","Enabled","Disabled","","user","Disabled","72:00:00","Scheduling data","Daily ","7:00:00 AM"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time"
"DESKTOP","\OneDrive Reporting","N/A","Ready","Interactive only","N/A","1","Microsoft","%localappdata%\Microsoft\OneDrive\OneDrive.exe","N/A","","Enabled","Disabled","","user","Disabled","72:00:00","Scheduling data","At logon time","N/A"
`

const withWSL = schtasksCSV +
	`"DESKTOP","\nodary","N/A","Ready","Interactive only","N/A","0","aweng","C:\Windows\System32\wsl.exe -d Ubuntu -u root /usr/bin/true","N/A","","Enabled","Disabled","","aweng","Disabled","72:00:00","Scheduling data","At logon time","N/A"
`

// 01 §8: a rebooted Windows host comes back with no agent unless something
// starts the distribution at logon, and 11 §2 makes that indistinguishable
// from any other unreachable node. The point of asking is that "stale" and
// "nobody ever started it" look identical and are fixed differently.
func TestALogonTaskIsFoundByWhatItRunsAndWhenItRuns(t *testing.T) {
	if got := parseLogonTasks(strings.NewReader(withWSL)); got != LogonTaskPresent {
		t.Errorf("a wsl.exe task at logon reads %q, want %q", got, LogonTaskPresent)
	}
	// OneDrive runs at logon and is not a WSL task; Acrobat runs wsl-nothing
	// daily. Neither brings a node back, and answering `present` for either
	// would be worse than not asking.
	if got := parseLogonTasks(strings.NewReader(schtasksCSV)); got != LogonTaskAbsent {
		t.Errorf("a host with no wsl logon task reads %q, want %q", got, LogonTaskAbsent)
	}
}

// Every way the answer can be "nobody knows", which is not "no".
func TestAnUnaskableHostSaysUnknownRatherThanAbsent(t *testing.T) {
	for _, c := range []struct{ what, csv string }{
		{"nothing at all", ""},
		{"columns this build does not recognise", "\"HostName\",\"TaskName\"\n\"A\",\"B\"\n"},
	} {
		if got := parseLogonTasks(strings.NewReader(c.csv)); got != LogonTaskUnknown {
			t.Errorf("%s reads %q, want %q — `absent` is a claim, and this is not one",
				c.what, got, LogonTaskUnknown)
		}
	}
}
