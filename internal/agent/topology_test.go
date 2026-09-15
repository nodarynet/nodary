package agent

import "testing"

// What an 8-GPU DGX prints. The affinity columns and the legend are the part
// this must ignore: they change between driver releases, and a parser that
// counted columns would start reading `0-31` as a link type.
const dgxTopo = `	GPU0	GPU1	GPU2	NIC0	CPU Affinity	NUMA Affinity	GPU NUMA ID
GPU0	 X 	NV12	SYS	PXB	0-31,64-95	0		N/A
GPU1	NV12	 X 	SYS	SYS	0-31,64-95	0		N/A
GPU2	SYS	SYS	 X 	SYS	32-63,96-127	1		N/A
NIC0	PXB	SYS	SYS	 X

Legend:

  X    = Self
  SYS  = Connection traversing PCIe as well as the SMP interconnect between NUMA nodes
  NV#  = Connection traversing a bonded set of # NVLinks
`

// R7-03: an operator assigning GPUs by index needs to know which of them
// belong together. Two cards on the same NVLink behave nothing like two that
// reach each other across the host bridge, and the second pair runs a
// tensor-parallel deployment slowly for no visible reason.
func TestTheTopologyMatrixIsReadWithoutTheAffinityColumns(t *testing.T) {
	got := parseTopology([]byte(dgxTopo))

	if len(got.GPUs) != 3 {
		t.Fatalf("gpus = %v, want the three GPU columns and not NIC0 or the affinities", got.GPUs)
	}
	if len(got.Matrix) != 3 {
		t.Fatalf("matrix has %d rows, want one per GPU: %v", len(got.Matrix), got.Matrix)
	}
	for _, c := range []struct {
		row, col int
		want     string
	}{
		{0, 0, "X"}, {0, 1, "NV12"}, {0, 2, "SYS"},
		{1, 0, "NV12"}, {1, 1, "X"},
		{2, 2, "X"},
	} {
		if got.Matrix[c.row][c.col] != c.want {
			t.Errorf("matrix[%d][%d] = %q, want %q", c.row, c.col, got.Matrix[c.row][c.col], c.want)
		}
	}
	// The vocabulary is nvidia-smi's, so the record says whose legend to read.
	if got.Source != "nvidia-smi topo -m" {
		t.Errorf("source = %q; the link words mean what nvidia-smi says they mean", got.Source)
	}
}

// A host with one card, none at all, or WSL2 where `topo` is not implemented.
// None of those is a fault, and a matrix invented for them would be a claim
// about hardware nobody made.
func TestATopologyWithNothingToSayIsEmpty(t *testing.T) {
	for _, c := range []struct{ what, out string }{
		{"nothing at all", ""},
		{"a legend and no matrix", "Legend:\n\n  X    = Self\n"},
		{"a heading with no rows", "\tGPU0\tCPU Affinity\n"},
	} {
		if got := parseTopology([]byte(c.out)); len(got.Matrix) != 0 || got.Source != "" {
			t.Errorf("%s produced %+v, want nothing", c.what, got)
		}
	}
}
