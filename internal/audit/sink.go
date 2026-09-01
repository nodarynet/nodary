package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nodarynet/nodary/internal/paths"
)

// A Sink is somewhere audit records are delivered after they are committed.
//
// Delivery is deliberately not part of the write path. The record exists once
// its transaction commits; a sink cannot roll that back and must not be able to
// block the next change either. The database is the authoritative copy, and
// `audit export --from-seq` is how a destination that fell behind catches up.
//
// The interface is what makes a network sink — Elastic, Splunk HEC, a plain
// NDJSON endpoint — additive rather than surgery on the write path
// (docs/tasks/R2-control-plane.md R2-41).
type Sink interface {
	// Emit delivers one record. line is canonical JSON with no trailing
	// newline; a sink that needs one adds it.
	Emit(ctx context.Context, seq int64, line []byte) error
	// Name is how this sink is named in a delivery failure, in the same form
	// the specification string uses.
	Name() string
	// Close releases anything held. Emitting after Close is a caller error.
	Close() error
}

// Sink specification forms. These are the durable part of the configuration:
// an environment variable carries them today and server.toml will carry them
// later, but both parse the same string.
const (
	SinksEnv   = "NODARY_AUDIT_SINKS"
	PostureEnv = "NODARY_AUDIT_ON_SINK_FAILURE"
)

// ErrBadSinkSpec is returned by ParseSinks and ParsePosture.
var ErrBadSinkSpec = errors.New("audit sink specification is not valid")

// ParseSinks reads a comma-separated specification: "file:/path", "stdout",
// "stderr", or "none".
//
// "none" must stand alone. Configuring it alongside a real sink is a
// contradiction rather than a preference, and silently picking one of the two
// readings is how an appliance ends up delivering nothing while its
// configuration says otherwise.
func ParseSinks(spec string) ([]Sink, error) {
	fields := strings.Split(spec, ",")
	var sinks []Sink
	seen := map[string]bool{}

	for _, raw := range fields {
		f := strings.TrimSpace(raw)
		if f == "" {
			return nil, fmt.Errorf("%w: %q has an empty entry", ErrBadSinkSpec, spec)
		}
		if seen[f] {
			return nil, fmt.Errorf("%w: %q appears twice", ErrBadSinkSpec, f)
		}
		seen[f] = true

		switch {
		case f == "none":
			if len(fields) != 1 {
				return nil, fmt.Errorf("%w: \"none\" cannot be combined with another sink", ErrBadSinkSpec)
			}
			return nil, nil
		case f == "stdout":
			sinks = append(sinks, &consoleSink{name: "stdout", w: os.Stdout})
		case f == "stderr":
			sinks = append(sinks, &consoleSink{name: "stderr", w: os.Stderr})
		case strings.HasPrefix(f, "file:"):
			// Trimmed again after the prefix, not only around the field. A
			// space after the colon is a natural way to write this in a
			// systemd Environment= line, and it used to land in the path:
			// "file: /var/log/nodary/audit.jsonl" is a *relative* path whose
			// first component is a directory named " ", so records went to a
			// tree under the process CWD while Name() still printed the
			// absolute path the operator had asked for.
			path := strings.TrimSpace(strings.TrimPrefix(f, "file:"))
			if path == "" {
				return nil, fmt.Errorf("%w: \"file:\" has no path", ErrBadSinkSpec)
			}
			sinks = append(sinks, NewFileSink(path))
		default:
			return nil, fmt.Errorf(
				"%w: %q is not one of file:PATH, stdout, stderr or none", ErrBadSinkSpec, f)
		}
	}
	return sinks, nil
}

// Posture is what happens when a sink refuses a record.
type Posture int

const (
	// Warn reports the failure and carries on. It is the default, including
	// for compliance deployments: NIST SP 800-171 3.3.4 asks for an alert on an
	// audit logging process failure, not a halt, and a full /var/log should not
	// stop an operator restarting a model.
	Warn Posture = iota

	// Block refuses the next mutation while a sink is failing. It cannot refuse
	// the one that failed — that record is already committed — and describing
	// it as anything stronger would misstate what a post-commit sink can do.
	Block
)

func (p Posture) String() string {
	if p == Block {
		return "block"
	}
	return "warn"
}

// ParsePosture reads "warn" or "block".
func ParsePosture(s string) (Posture, error) {
	switch strings.TrimSpace(s) {
	case "warn":
		return Warn, nil
	case "block":
		return Block, nil
	}
	return Warn, fmt.Errorf("%w: %q is not warn or block", ErrBadSinkSpec, s)
}

// Delivery is the set of sinks a Log writes to and what it does when one fails.
type Delivery struct {
	sinks   []Sink
	posture Posture
	warn    io.Writer

	mu      sync.Mutex
	failing map[string]error
}

// NewDelivery builds a Delivery. warn is where a degraded-delivery message
// goes; nil means os.Stderr, per docs/specs/10-cli.md §4, which reserves stdout
// for a command's own output.
func NewDelivery(sinks []Sink, posture Posture, warn io.Writer) *Delivery {
	if warn == nil {
		warn = os.Stderr
	}
	return &Delivery{sinks: sinks, posture: posture, warn: warn, failing: map[string]error{}}
}

// DeliveryFromEnv builds a Delivery from NODARY_AUDIT_SINKS and
// NODARY_AUDIT_ON_SINK_FAILURE, defaulting to the JSONL file and "warn".
func DeliveryFromEnv(warn io.Writer) (*Delivery, error) {
	spec := os.Getenv(SinksEnv)
	if spec == "" {
		spec = "file:" + paths.AuditLog()
	}
	sinks, err := ParseSinks(spec)
	if err != nil {
		return nil, err
	}
	posture := Warn
	if p := os.Getenv(PostureEnv); p != "" {
		if posture, err = ParsePosture(p); err != nil {
			return nil, err
		}
	}
	return NewDelivery(sinks, posture, warn), nil
}

// warnf reports a delivery problem on the warn writer.
//
// Every write to warn goes through here, under d.mu: the writer is supplied by
// the caller — a *bytes.Buffer in tests, a bufio.Writer in a server — and
// nothing about io.Writer promises it is safe for concurrent use.
func (d *Delivery) warnf(format string, a ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.warn, format, a...)
}

// Emit delivers a committed record to every sink.
//
// It returns nothing. The record is already in the database, so a sink failure
// is not the outcome of the action and must not be reported as one — it is
// announced on the warn writer and remembered, which is what Blocked reads.
func (d *Delivery) Emit(ctx context.Context, seq int64, line []byte) {
	for _, s := range d.sinks {
		err := s.Emit(ctx, seq, line)
		d.mu.Lock()
		switch {
		case err != nil:
			// Announced once per transition rather than on every record, so a
			// sink that is down for an hour does not bury the reason it went
			// down under thousands of identical lines.
			if _, already := d.failing[s.Name()]; !already {
				fmt.Fprintf(d.warn, "nodary: audit delivery to %s is failing: %v\n", s.Name(), err)
			}
			d.failing[s.Name()] = err
		default:
			if _, was := d.failing[s.Name()]; was {
				fmt.Fprintf(d.warn, "nodary: audit delivery to %s has recovered at record %d\n",
					s.Name(), seq)
				delete(d.failing, s.Name())
			}
		}
		d.mu.Unlock()
	}
}

// Blocked reports why the next mutation must be refused, or nil.
//
// Under Warn it is always nil: the posture is the whole difference between the
// two, so there is one place that difference lives.
func (d *Delivery) Blocked() error {
	if d.posture != Block {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.failing) == 0 {
		return nil
	}
	names := make([]string, 0, len(d.failing))
	for name := range d.failing {
		names = append(names, name)
	}
	sort.Strings(names)
	// Every cause, not just the first name's: a caller deciding whether to
	// retry or to page reaches for errors.Is/errors.As, and with two sinks down
	// the second reason used to survive only as a name inside a formatted
	// string.
	causes := make([]error, len(names))
	for i, name := range names {
		causes[i] = d.failing[name]
	}
	return fmt.Errorf("audit delivery to %s is failing and the policy is block: %w",
		strings.Join(names, ", "), errors.Join(causes...))
}

// Sinks reports the configured sinks, so a caller can refuse a combination its
// own output discipline forbids — a command that writes a document to stdout
// cannot also emit records there (docs/specs/10-cli.md §4).
func (d *Delivery) Sinks() []Sink { return d.sinks }

// Close closes every sink.
func (d *Delivery) Close() error {
	var errs []error
	for _, s := range d.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing %s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// consoleSink writes to an already-open stream. It never closes it: os.Stdout
// does not belong to this package.
type consoleSink struct {
	name string
	w    io.Writer
}

func (c *consoleSink) Name() string { return c.name }
func (c *consoleSink) Close() error { return nil }

func (c *consoleSink) Emit(_ context.Context, _ int64, line []byte) error {
	_, err := c.w.Write(append(append(make([]byte, 0, len(line)+1), line...), '\n'))
	return err
}

// FileSink is the append-only JSONL mirror of docs/specs/07-identity-audit.md
// §3, and the artefact docs/specs/11-failure-modes.md §5 relies on when the
// database is lost.
type FileSink struct {
	path string
}

// NewFileSink returns a sink appending to path.
func NewFileSink(path string) *FileSink { return &FileSink{path: path} }

func (f *FileSink) Name() string { return "file:" + f.path }
func (f *FileSink) Close() error { return nil }

// Emit appends one line and flushes it to disk.
//
// The file is opened per record rather than held open for the process lifetime.
// An append-only log is the thing most likely to be rotated by something
// outside nodary, and a held descriptor goes on writing into the unlinked
// inode; reopening by path makes rename-and-create rotation safe. (copytruncate
// is unsafe against any appender and must not be used.) The cost is one open
// and one fsync per operator action, which is not a hot path.
func (f *FileSink) Emit(_ context.Context, _ int64, line []byte) error {
	created, err := f.ensureDir()
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, paths.ModeAuditLog)
	if err != nil {
		return fmt.Errorf("opening %s: %w", f.path, err)
	}
	defer fh.Close()

	// One Write, so O_APPEND's atomicity covers the whole line and two
	// processes appending at once cannot interleave halves of two records.
	if _, err := fh.Write(append(append(make([]byte, 0, len(line)+1), line...), '\n')); err != nil {
		return fmt.Errorf("appending to %s: %w", f.path, err)
	}
	if err := fh.Sync(); err != nil {
		return fmt.Errorf("flushing %s: %w", f.path, err)
	}
	if created {
		// Without this the file's directory entry can be lost to a power cut
		// even though its contents were flushed.
		if err := syncDir(filepath.Dir(f.path)); err != nil {
			return err
		}
	}
	return nil
}

// ensureDir creates the log directory if it is absent, and reports whether the
// log file did not yet exist.
//
// An existing directory is left exactly as it is, which is a deliberate
// difference from the database directory. A database at 0644 is a leak with no
// legitimate cause, so store tightens it; an audit log has one — a shipper
// running as its own account has to read the file. Creating is where the closed
// default is set; an operator who widened it afterwards meant to.
func (f *FileSink) ensureDir() (created bool, err error) {
	if _, err := os.Stat(f.path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("reading %s: %w", f.path, err)
	}
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, paths.ModeLogDir); err != nil {
		return false, fmt.Errorf("creating %s: %w", dir, err)
	}
	return true, nil
}

func syncDir(dir string) error {
	fh, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dir, err)
	}
	defer fh.Close()
	if err := fh.Sync(); err != nil {
		return fmt.Errorf("flushing %s: %w", dir, err)
	}
	return nil
}
