package api

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nodarynet/nodary/internal/derive"
)

// StubBuild swaps the build seam for the length of one test, so the external
// test package can drive POST /backends/{name}/build without a container
// runtime — which is exactly what a test has not got, and which none of what
// the endpoint decides depends on.
//
// Declared in a _test.go file in this package rather than as production
// surface: the seam exists for the test and should not outlive it.
func StubBuild(t *testing.T, digest string) *Stubbed {
	t.Helper()
	st := &Stubbed{}
	prevBuild, prevRun := buildDerive, buildRuntime
	buildDerive = func(_ context.Context, o derive.Options) (derive.Result, error) {
		st.Builds++
		st.Asked = o
		if st.FailBuild != "" {
			return derive.Result{}, errors.New(st.FailBuild)
		}
		return derive.Result{Image: o.Tag, Digest: digest, Steps: 1,
			Reached: []string{"pypi.internal:443"}}, nil
	}
	buildRuntime = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 2 && args[0] == "save" && args[1] == "-o" {
			st.Saved = append(st.Saved, args[len(args)-1])
			return nil, os.WriteFile(args[2], []byte("a tar of "+args[len(args)-1]), 0o600)
		}
		return nil, nil
	}
	t.Cleanup(func() { buildDerive, buildRuntime = prevBuild, prevRun })
	return st
}

// Stubbed is what the stub saw.
type Stubbed struct {
	Builds    int
	Asked     derive.Options
	Saved     []string
	FailBuild string
}
