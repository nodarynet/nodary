package backend

import "sort"

// VendorNVIDIA is the vendor an empty one means.
//
// agent.GPU.VendorName's default and the component manifest's base entry: every
// image nodary pins is a CUDA build, and a vendor key names what differs from
// that rather than restating it. A GPU offered before there was a vendor axis
// at all comes back with no vendor and is one of these.
const VendorNVIDIA = "nvidia"

// silicon is internal/preflight's vendor vocabulary and nothing finer.
// dev/plans/R6b-the-silicon-matrix.md §2 is why three names are enough: the
// splits that would need more of them — ROCm or not, RDNA or CDNA — exist only
// inside images this release does not pin. Widening it is a decision with a
// plan behind it, not a word somebody adds here.
//
// Not imported from internal/preflight: that package probes a host, and a
// descriptor parser that cannot run on a machine with no GPU at all is worse
// than three strings written twice.
var silicon = []string{VendorNVIDIA, "amd", "intel"}

// recommended is nodary's own preference, most-preferred first.
//
// **The split that matters.** Which silicon a backend *can* run on is a fact
// about the backend, so the descriptor declares it (dev/specs/04-backends.md
// §6). Which of several eligible backends nodary *suggests* is nodary's
// opinion, so it lives here — a descriptor that could declare itself
// recommended would let two claim it, and would let an operator's own
// descriptor outrank the ones this build pins and tests.
//
// One ordered list rather than a table per vendor, and it reproduces
// dev/plans/R6b-the-silicon-matrix.md §3 exactly: on NVIDIA every entry is
// eligible so the answer is sglang; on AMD and Intel the first two are not, so
// the answer is llama-cpp. A row per vendor would be a second place for the
// matrix to be written down, and the descriptors are the first.
//
// A backend nodary does not pin is offered but never recommended: this build
// has no basis for suggesting an image it has not tested.
var recommended = []string{"sglang", "vllm", "llama-cpp"}

// runsOn is whether a declared silicon list covers a vendor.
func runsOn(declared []string, vendor string) bool {
	if vendor == "" {
		vendor = VendorNVIDIA
	}
	return contains(declared, vendor)
}

// RunsOn is whether this backend declares it runs on a vendor's silicon.
func (d Descriptor) RunsOn(vendor string) bool { return runsOn(d.Backend.Silicon, vendor) }

// RunsOn is the same question of a rendered report, which is what both front
// ends hold and what crosses the wire — so the CLI asks it identically whether
// it read the registry locally or over --server.
func (r Report) RunsOn(vendor string) bool { return runsOn(r.Silicon, vendor) }

// Offer is the backends that run on a vendor's silicon and which one to
// recommend — dev/plans/R6b-the-silicon-matrix.md §3.
//
// One function, read by `model register` and by the install wizard, because two
// places that decide which backends are legal will disagree and the wizard is
// where a first-time operator meets the question.
//
// The recommendation is empty when nothing this build pins is eligible. That is
// not the same as having nothing to offer: a site whose only AMD-capable
// descriptor is one it registered itself gets it offered and gets no
// suggestion, which is the honest answer rather than a guess dressed as advice.
func Offer(all []Report, vendor string) (offer []string, recommend string) {
	for _, r := range all {
		if r.RunsOn(vendor) {
			offer = append(offer, r.Name)
		}
	}
	sort.Strings(offer)
	for _, name := range recommended {
		if contains(offer, name) {
			return offer, name
		}
	}
	return offer, ""
}
