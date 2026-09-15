package dataplane_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/dataplane"
)

// TestNothingOutsideThisPackageNamesAPlane is what the seam is for.
//
// Before internal/dataplane existed, LiteLLM was named in nine places — the
// gateway's attribution header, the installer's unit, the configuration writer,
// the image pin, the applied marker, the restart order, the unit lists — and
// each one would have become a conditional the day a second plane arrived.
// R3-17's whole deliverable is that those nine became one, and the only way a
// tenth does not get written next month is for the build to say so.
//
// **Code, not prose.** The files are parsed without comments, so a comment
// explaining why LiteLLM behaves as it does is left alone; what is refused is an
// identifier or a string literal — `nodary-litellm.service`, `litellm.yaml`,
// `NODARY_LITELLM_IMAGE`, `X-Litellm-Model-Id` — because those are the ones that
// make a code path specific to one implementation.
//
// **Tests are excluded, deliberately.** A test that names the plane a host
// actually installs is asserting something true about that plane — that its
// image is digest-pinned, that its unit puts no credential on a command line —
// and forcing it through the seam would test the seam instead of the thing.
//
// The vocabulary comes from dataplane.Names, so a plane added here is covered
// without anybody remembering to extend this.
func TestNothingOutsideThisPackageNamesAPlane(t *testing.T) {
	names := dataplane.Names()
	if len(names) == 0 {
		t.Fatal("no planes to check for")
	}

	// ".." is internal/, which is every package that could name one. cmd/ is a
	// dozen lines of flag handling over this tree and holds no plane-specific
	// path.
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "dataplane":
			return fs.SkipDir // the implementation, which is the point
		case d.IsDir(), !strings.HasSuffix(path, ".go"), strings.HasSuffix(path, "_test.go"):
			return nil
		}

		// Mode 0, not parser.ParseComments: a comment is prose about the
		// product and may say whatever is true.
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var text string
			switch v := n.(type) {
			case *ast.Ident:
				text = v.Name
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					text = v.Value
				}
			}
			low := strings.ToLower(text)
			for _, name := range names {
				if strings.Contains(low, name) {
					t.Errorf("%s names the %s data plane in code: %s\n"+
						"  Everything specific to one plane belongs in internal/dataplane, "+
						"reached through the Plane value server.toml selects. A name here is "+
						"a conditional the second plane has to grow.", path, name, text)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
