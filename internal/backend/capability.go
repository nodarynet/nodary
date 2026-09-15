package backend

import (
	"fmt"
	"sort"
	"strings"
)

// CheckParams is dev/specs/04-backends.md §7: capabilities are enforced at
// enable time, not discovered at crash time.
//
// The whole value of this is *where* it runs. The agent already refuses a
// deployment whose parameters the descriptor cannot render (R6-03), but that
// happens on a GPU host up to a minute later, and what an operator sees is a
// deployment that was accepted and then did not start. Called from the
// applier, the refusal arrives in the preview, in front of the person who
// wrote the mistake, before anything is staged.
//
// `gpus` is how many cards the deployment was assigned; 0 means the caller did
// not measure, and the count check is skipped rather than reported as zero.
func (d Descriptor) CheckParams(p Params, gpus int) error {
	b := d.Backend
	for _, c := range []struct {
		name      string
		supported bool
	}{
		{"tensor_parallel", b.Capabilities.TensorParallel},
		{"expert_parallel", b.Capabilities.ExpertParallel},
	} {
		n, set, err := degree(p, c.name)
		if err != nil {
			return err
		}
		// 1 is not parallelism, it is the absence of it. Refusing it would
		// make a document that spells out its defaults unportable between
		// backends for no difference in what runs.
		if !set || n <= 1 {
			continue
		}
		if !c.supported {
			return fmt.Errorf("%w: %s does not support %s%s",
				ErrUnsupported, b.Name, strings.ReplaceAll(c.name, "_", " "), d.insteadTry())
		}
		// A degree higher than the cards it has is a container that starts,
		// waits for ranks that never appear, and is killed by the ready
		// timeout half an hour later.
		if gpus > 0 && n > gpus {
			return fmt.Errorf("%w: %s %d exceeds the %d GPU%s assigned to this deployment",
				ErrUnsupported, strings.ReplaceAll(c.name, "_", " "), n, gpus, plural(gpus))
		}
	}

	// The quantization the deployment asks for against the list the descriptor
	// declares. Requesting a scheme the backend cannot load is a server that
	// reads the weights, fails to interpret them, and reports a format error
	// naming neither the parameter nor the backend.
	if v, ok := p["quantization"]; ok {
		want, err := scalar(v)
		if err != nil {
			return fmt.Errorf("%w: quantization: %v", ErrUnsupported, err)
		}
		if !contains(b.Capabilities.Quantization, want) {
			have := "nothing"
			if len(b.Capabilities.Quantization) > 0 {
				have = strings.Join(b.Capabilities.Quantization, ", ")
			}
			return fmt.Errorf("%w: %s does not support %q quantization; it supports %s",
				ErrUnsupported, b.Name, want, have)
		}
	}
	return nil
}

// insteadTry names what this backend *does* have, out of the descriptor rather
// than out of a table in this file.
//
// dev/specs/04-backends.md §1's argument for descriptors over plugins is that
// a backend's facts belong in its own data. A hint hard-coded here — "use
// --tensor-split" — would be exactly the backend knowledge in nodary's code
// that the format exists to hold instead, and it would go stale silently the
// first time a backend changed its options. `[backend.extra]` already means
// "options this backend names and nodary only passes through", which is where
// the alternative to an unsupported capability always lives.
func (d Descriptor) insteadTry() string {
	if len(d.Backend.Extra) == 0 {
		return ""
	}
	names := make([]string, 0, len(d.Backend.Extra))
	for k := range d.Backend.Extra {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Sprintf(". It names %s, which reach it unchanged", strings.Join(names, ", "))
}

// degree reads a parallelism degree, which must be a whole number.
//
// JSON numbers arrive as float64, so 2 is 2.0 here and 2.5 is a document that
// would otherwise render `--tensor-parallel-size=2` or `=2.500000` depending on
// which code path reached it first.
func degree(p Params, name string) (int, bool, error) {
	v, ok := p[name]
	if !ok {
		return 0, false, nil
	}
	s, err := scalar(v)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %s: %v", ErrUnsupported, name, err)
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || fmt.Sprint(n) != s {
		return 0, false, fmt.Errorf("%w: %s must be a whole number, not %q", ErrUnsupported, name, s)
	}
	if n < 1 {
		return 0, false, fmt.Errorf("%w: %s must be at least 1, not %d", ErrUnsupported, name, n)
	}
	return n, true, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
