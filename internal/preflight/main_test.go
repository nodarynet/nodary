package preflight

import (
	"context"
	"os"
	"testing"
)

// The logon-task query runs a Windows binary, which costs about two seconds
// each time and is not what any test in this package is checking. Stubbed once
// for the whole package; logontask_test.go drives the parser directly, which
// is where the logic actually is.
func TestMain(m *testing.M) {
	logonTask = func(context.Context) string { return LogonTaskNotWSL }
	os.Exit(m.Run())
}
