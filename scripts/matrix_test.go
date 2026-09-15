package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/backend"
)

// The published matrix is a claim a buyer acts on before they own the hardware,
// and it is maintained by hand in two documents against three descriptors.
//
// dev/plans/R6b-the-silicon-matrix.md §3 is the table; the descriptors are what
// `nodary model register` actually does. A row that is merely stale reads
// exactly like a row that is current — the same reason the milestone counts
// above are checked rather than trusted — and the cost of a stale one here is
// somebody buying a card for a backend that will refuse it.
func TestThePublishedMatrixIsWhatTheDescriptorsDo(t *testing.T) {
	all, err := backend.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reports := backend.Reports(all)

	// What each document claims, transcribed from the row a reader sees. The
	// spellings differ between them on purpose: the README is prose for a buyer
	// and the guide is the flag an operator types.
	for _, doc := range []struct {
		path string
		rows map[string][]string
	}{
		{"README.md", map[string][]string{
			"nvidia": {"SGLang", "vLLM", "llama.cpp"},
			"amd":    {"llama.cpp on Vulkan"},
			"intel":  {"llama.cpp on Vulkan"},
		}},
		{filepath.Join("docs", "administering.md"), map[string][]string{
			"nvidia": {"`sglang`", "`vllm`", "`llama-cpp`"},
			"amd":    {"`llama-cpp`"},
			"intel":  {"`llama-cpp`"},
		}},
	} {
		body, err := os.ReadFile(filepath.Join("..", doc.path))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if !strings.Contains(text, "Which backend runs on which GPU") {
			t.Errorf("%s no longer publishes the matrix at all", doc.path)
			continue
		}
		for vendor, want := range doc.rows {
			offer, _ := backend.Offer(reports, vendor)
			if len(offer) != len(want) {
				t.Errorf("%s: the %s row lists %d backends and this build offers %d (%v)",
					doc.path, vendor, len(want), len(offer), offer)
			}
			// Every backend the row names is one this build would offer, by the
			// name the row uses for it.
			for _, name := range want {
				if !rowNames(offer, name) {
					t.Errorf("%s: the %s row names %s, which this build does not offer there (%v)",
						doc.path, vendor, name, offer)
				}
			}
		}
	}

	// And the recommendation, which is the one cell a reader is most likely to
	// act on without reading the rest.
	for vendor, want := range map[string]string{
		"nvidia": "sglang", "amd": "llama-cpp", "intel": "llama-cpp",
	} {
		if _, got := backend.Offer(reports, vendor); got != want {
			t.Errorf("this build recommends %q on %s; both documents say %q", got, vendor, want)
		}
	}
}

// rowNames matches a document's spelling of a backend against the descriptor
// names — "llama.cpp on Vulkan" and "`llama-cpp`" are both llama-cpp.
func rowNames(offer []string, published string) bool {
	norm := func(s string) string {
		return strings.NewReplacer(".", "", "-", "", "`", "", " ", "").Replace(strings.ToLower(s))
	}
	p := norm(published)
	for _, name := range offer {
		if strings.HasPrefix(p, norm(name)) {
			return true
		}
	}
	return false
}
