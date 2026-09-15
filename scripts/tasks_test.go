package scripts

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// dev/status.md's milestone table is a claim about what this product does, in
// the place a reader is sent to find out — the same kind of statement
// [dev/plans/pilot.md]'s Tier 0 is about. It is maintained by hand against ten
// tracker files, and it had drifted on three rows before this test existed:
// work that landed and rows that were added both moved the denominators and the
// page kept the old numbers.
//
// A number that is merely stale reads exactly like a number that is current.
//
// It lived on the front page until the table moved here; the test moved with it
// rather than being deleted, because the hazard follows the table and not the
// file it sits in.

var (
	// The `a`/`b` suffix is a sub-task split out of a numbered one after the
	// fact (R4-01a, R6-04a). They are rows like any other and count like any
	// other; a pattern that missed them would quietly report a smaller
	// milestone than the tracker holds.
	taskRow   = regexp.MustCompile(`(?m)^- \[([ x])\] \*\*(R\d+)-\d+[a-z]?\*\*`)
	statusRow = regexp.MustCompile(`(?m)^\| \*\*(R\d+)\*\* [^|]*\| (\d+) of (\d+) \|`)
	// The tracker's own index counts what is *open*, where the status page counts
	// what is done. Both are "N of M" over the same M, which is the only reason
	// one test can hold both.
	indexRow   = regexp.MustCompile(`(?m)^\| \*\*\[(R\d+)\]\([^)]*\)\*\*(?:[^|]*\|){4}\s*\*{0,2}(\d+) of (\d+)\*{0,2}\s*\|`)
	trackerDir = filepath.Join("..", "dev", "tasks")
)

type counted struct{ done, total int }

// countTrackers reads every milestone tracker and counts its checkboxes.
func countTrackers(t *testing.T) map[string]counted {
	t.Helper()
	entries, err := os.ReadDir(trackerDir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]counted{}
	for _, e := range entries {
		if e.Name() == "README.md" || filepath.Ext(e.Name()) != ".md" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(trackerDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range taskRow.FindAllStringSubmatch(string(body), -1) {
			c := out[m[2]]
			c.total++
			if m[1] == "x" {
				c.done++
			}
			out[m[2]] = c
		}
	}
	if len(out) == 0 {
		t.Fatalf("no task rows found under %s", trackerDir)
	}
	return out
}

func TestTheStatusPageMilestoneCountsMatchTheTrackers(t *testing.T) {
	tracked := countTrackers(t)

	body, err := os.ReadFile(filepath.Join("..", "dev", "status.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows := statusRow.FindAllStringSubmatch(string(body), -1)
	if len(rows) == 0 {
		t.Fatal("no milestone rows found in dev/status.md; has the table's shape changed, " +
			"or moved again? A count nothing checks is the one that goes stale.")
	}

	claimed := map[string]bool{}
	for _, m := range rows {
		milestone, done, total := m[1], atoi(t, m[2]), atoi(t, m[3])
		claimed[milestone] = true
		got, ok := tracked[milestone]
		if !ok {
			t.Errorf("dev/status.md claims %s is %d of %d, and no tracker has any %s row",
				milestone, done, total, milestone)
			continue
		}
		if done != got.done || total != got.total {
			t.Errorf("dev/status.md claims %s is %d of %d; the tracker says %d of %d.\n"+
				"  This page is where a reader is sent to find out, and a stale number reads "+
				"exactly like a current one.", milestone, done, total, got.done, got.total)
		}
	}

	// A milestone with work done and no row is the same defect in the other
	// direction: the reader is told about eight milestones and there are nine.
	var missing []string
	for milestone, c := range tracked {
		if !claimed[milestone] && c.done > 0 {
			missing = append(missing, fmt.Sprintf("%s (%d of %d)", milestone, c.done, c.total))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the status page's table omits milestones that have landed work: %v", missing)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// And the tracker's own index, which counts the same rows from the other end.
// It carried "0 of 36" for a milestone with 38 rows and a bare "37" for one
// with 41: two different shapes, both stale, in the table that tells a reader
// which file to open.
func TestTheTrackerIndexCountsMatchTheTrackers(t *testing.T) {
	tracked := countTrackers(t)

	body, err := os.ReadFile(filepath.Join(trackerDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows := indexRow.FindAllStringSubmatch(string(body), -1)
	if len(rows) != len(tracked) {
		t.Errorf("the index lists %d milestones and there are %d tracker files; every "+
			"milestone gets a row, and every row says `open of total`", len(rows), len(tracked))
	}
	for _, m := range rows {
		milestone, open, total := m[1], atoi(t, m[2]), atoi(t, m[3])
		got, ok := tracked[milestone]
		if !ok {
			t.Errorf("the index lists %s and no tracker has any %s row", milestone, milestone)
			continue
		}
		if open != got.total-got.done || total != got.total {
			t.Errorf("the index says %s is %d open of %d; the tracker says %d open of %d",
				milestone, open, total, got.total-got.done, got.total)
		}
	}
}
