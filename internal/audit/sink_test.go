package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func names(sinks []Sink) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Name())
	}
	return out
}

func TestParseSinks(t *testing.T) {
	for spec, want := range map[string][]string{
		"stdout":                           {"stdout"},
		"stderr":                           {"stderr"},
		"file:/var/log/nodary/audit.jsonl": {"file:/var/log/nodary/audit.jsonl"},
		"file:/a.jsonl,stderr":             {"file:/a.jsonl", "stderr"},
		" stderr , file:/a.jsonl ":         {"stderr", "file:/a.jsonl"},
		"file:/a.jsonl,file:/b.jsonl":      {"file:/a.jsonl", "file:/b.jsonl"},
		"none":                             nil,
	} {
		t.Run(spec, func(t *testing.T) {
			got, err := ParseSinks(spec)
			if err != nil {
				t.Fatalf("ParseSinks(%q): %v", spec, err)
			}
			if len(want) == 0 && len(got) != 0 {
				t.Fatalf("got %v, want no sinks", names(got))
			}
			if len(want) > 0 && !reflect.DeepEqual(names(got), want) {
				t.Errorf("got %v, want %v", names(got), want)
			}
		})
	}
}

func TestParseSinksRejections(t *testing.T) {
	for name, spec := range map[string]string{
		"empty":             "",
		"empty entry":       "stderr,",
		"unknown":           "syslog",
		"unknown scheme":    "http://example.invalid",
		"file with no path": "file:",
		"duplicate":         "stderr,stderr",
		// "none" alongside a real sink is a contradiction, not a preference.
		// Choosing either reading silently is how an appliance delivers nothing
		// while its configuration says it delivers somewhere.
		"none with another": "none,file:/a.jsonl",
		"another with none": "file:/a.jsonl,none",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSinks(spec); !errors.Is(err, ErrBadSinkSpec) {
				t.Errorf("ParseSinks(%q) error = %v, want ErrBadSinkSpec", spec, err)
			}
		})
	}
}

func TestParsePosture(t *testing.T) {
	for s, want := range map[string]Posture{"warn": Warn, "block": Block, " block ": Block} {
		got, err := ParsePosture(s)
		if err != nil || got != want {
			t.Errorf("ParsePosture(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := ParsePosture("halt"); !errors.Is(err, ErrBadSinkSpec) {
		t.Errorf("error = %v, want ErrBadSinkSpec", err)
	}
	if got := Block.String(); got != "block" {
		t.Errorf("Block.String() = %q", got)
	}
}

func TestDeliveryFromEnvDefaultsToTheJSONLFile(t *testing.T) {
	t.Setenv(SinksEnv, "")
	t.Setenv(PostureEnv, "")
	d, err := DeliveryFromEnv(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(d.Sinks()); len(got) != 1 || !strings.HasPrefix(got[0], "file:") {
		t.Errorf("default sinks = %v, want one file sink", got)
	}
	if d.posture != Warn {
		t.Errorf("default posture = %v, want warn", d.posture)
	}

	t.Setenv(SinksEnv, "stderr")
	t.Setenv(PostureEnv, "block")
	d, err = DeliveryFromEnv(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(d.Sinks()); !reflect.DeepEqual(got, []string{"stderr"}) {
		t.Errorf("sinks = %v", got)
	}
	if d.posture != Block {
		t.Errorf("posture = %v, want block", d.posture)
	}

	t.Setenv(PostureEnv, "halt")
	if _, err := DeliveryFromEnv(io.Discard); err == nil {
		t.Error("an unknown posture was accepted")
	}
}

func TestFileSinkAppendsWholeLinesAndCreatesClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	path := filepath.Join(dir, "audit.jsonl")
	s := NewFileSink(path)

	for i := range 3 {
		if err := s.Emit(context.Background(), int64(i+1), []byte(fmt.Sprintf(`{"seq":%d}`, i+1))); err != nil {
			t.Fatal(err)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3}\n"
	if string(b) != want {
		t.Errorf("file = %q, want %q", b, want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("audit log created %#o, want 0600", got)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("log directory created %#o, want nothing for group or other", got)
	}
}

// A shipper running as its own account has to read the file, so an operator who
// widened the directory meant to. The database directory is tightened on every
// open because a database at 0644 has no legitimate cause; this one does.
func TestFileSinkLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	s := NewFileSink(path)
	// Twice: the first Emit takes the create path and the second the
	// already-exists path, and either could be where a chmod crept in.
	for i := range 2 {
		if err := s.Emit(context.Background(), int64(i+1), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o750 {
		t.Errorf("an existing log directory was changed to %#o", got)
	}
}

func TestFileSinkReportsAFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: open fails on every attempt.
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := NewFileSink(path).Emit(context.Background(), 1, []byte(`{}`))
	if err == nil {
		t.Fatal("emitting into a directory succeeded")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the path", err)
	}
}

// Reopening by path per record is what makes rename-and-create rotation safe.
func TestFileSinkFollowsARename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s := NewFileSink(path)
	ctx := context.Background()

	if err := s.Emit(ctx, 1, []byte(`{"seq":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(ctx, 2, []byte(`{"seq":2}`)); err != nil {
		t.Fatal(err)
	}

	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(rotated) != "{\"seq\":1}\n" || string(current) != "{\"seq\":2}\n" {
		t.Errorf("after rotation: rotated=%q current=%q", rotated, current)
	}
}

func TestFileSinkAppendsAtomicallyUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s := NewFileSink(path)
	line := []byte(`{"seq":0,"pad":"` + strings.Repeat("x", 4096) + `"}`)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				if err := s.Emit(context.Background(), 0, line); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(got) != 16*8 {
		t.Fatalf("%d lines, want %d", len(got), 16*8)
	}
	for i, l := range got {
		if l != string(line) {
			t.Fatalf("line %d was torn: %q", i, l)
		}
	}
}

// flaky fails until it is told to stop.
type flaky struct {
	mu   sync.Mutex
	fail bool
	got  [][]byte
}

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Close() error { return nil }
func (f *flaky) Emit(_ context.Context, _ int64, line []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("the endpoint is unreachable")
	}
	f.got = append(f.got, append([]byte(nil), line...))
	return nil
}

func TestWarnPostureReportsOnceAndNeverBlocks(t *testing.T) {
	var warn bytes.Buffer
	f := &flaky{fail: true}
	d := NewDelivery([]Sink{f}, Warn, &warn)

	for i := range 5 {
		d.Emit(context.Background(), int64(i+1), []byte(`{}`))
		if err := d.Blocked(); err != nil {
			t.Fatalf("warn posture blocked: %v", err)
		}
	}
	if got := strings.Count(warn.String(), "is failing"); got != 1 {
		t.Errorf("reported the same failure %d times, want once", got)
	}

	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	d.Emit(context.Background(), 6, []byte(`{}`))
	if !strings.Contains(warn.String(), "has recovered at record 6") {
		t.Errorf("recovery was not announced:\n%s", warn.String())
	}
}

func TestBlockPostureRefusesTheNextActionUntilRecovery(t *testing.T) {
	var warn bytes.Buffer
	f := &flaky{}
	d := NewDelivery([]Sink{f}, Block, &warn)

	if err := d.Blocked(); err != nil {
		t.Fatalf("blocked before anything failed: %v", err)
	}

	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	d.Emit(context.Background(), 1, []byte(`{}`))

	err := d.Blocked()
	if err == nil {
		t.Fatal("block posture did not refuse after a delivery failure")
	}
	if !strings.Contains(err.Error(), "flaky") {
		t.Errorf("error = %v, want it to name the sink", err)
	}

	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	d.Emit(context.Background(), 2, []byte(`{}`))
	if err := d.Blocked(); err != nil {
		t.Errorf("still blocked after recovery: %v", err)
	}
}

// One failing sink must not stop the others: a record that reached the file is
// evidence whether or not it also reached a second destination.
func TestOneFailingSinkDoesNotStopTheOthers(t *testing.T) {
	good, bad := &flaky{}, &flaky{fail: true}
	d := NewDelivery([]Sink{bad, good}, Warn, io.Discard)
	d.Emit(context.Background(), 1, []byte(`{"seq":1}`))

	good.mu.Lock()
	defer good.mu.Unlock()
	if len(good.got) != 1 {
		t.Errorf("the healthy sink received %d records, want 1", len(good.got))
	}
}

func TestConsoleSinkWritesOneLine(t *testing.T) {
	var buf bytes.Buffer
	c := &consoleSink{name: "test", w: &buf}
	if err := c.Emit(context.Background(), 1, []byte(`{"seq":1}`)); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "{\"seq\":1}\n" {
		t.Errorf("wrote %q", got)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
