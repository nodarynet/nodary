package audit

import (
	"context"
	"fmt"
	"log/syslog"
	"net/url"
	"strings"
)

// syslogTag is the program name every record is emitted under, so a collector
// can select nodary's records without matching on their content.
const syslogTag = "nodary"

// syslogFacility is authpriv rather than daemon or local0.
//
// These are security-relevant records naming who did what, and authpriv is the
// facility every default rsyslog configuration already routes to a
// root-readable file rather than to the general message stream. local0 would
// need the site to configure something before the records landed anywhere
// sensible, and a sink that silently goes to /var/log/messages beside cron
// chatter is one nobody reads.
const syslogFacility = syslog.LOG_AUTHPRIV

// syslogSink delivers records to a syslog daemon, which is the off-box hop a
// site with no SIEM already has.
//
// **Why this exists.** The default sink is the JSONL file beside the database
// (FileSink), and that mirror lives on the same disk as the chain it mirrors —
// so a control plane somebody owns can rewrite both. dev/specs/07-identity-audit.md
// §3's whole argument for shipping records off-box is that a compromised
// appliance cannot quietly rewrite a copy that already left the machine, and
// R2-41's HTTP sink assumes a SIEM endpoint to send it to. A small site has no
// SIEM and does have syslog: rsyslog forwarding to a collector, an MSP's agent,
// a NAS, a firewall. This hands the destination problem to whatever the site
// already runs, and nodary learns nothing about it.
//
// **The limit, stated rather than implied.** Syslog truncates: RFC 3164
// receivers are entitled to cut a message at 1024 bytes, and implementations
// vary above that. A record with a large detail carries fine in the database
// and may arrive here cut in half. So this stream is the monitoring and
// alerting copy; the file mirror and `audit export --from-seq` remain the
// evidentiary one, and a verifier is never pointed at a syslog capture. The
// line is emitted as unmodified canonical JSON so a collector can parse it —
// prefixing a sequence number would survive truncation better and would stop
// every JSON-aware collector from reading any of it.
type syslogSink struct {
	spec string
	w    *syslog.Writer
}

// newSyslogSink dials the daemon named by a `syslog:` specification.
//
// Dialing at construction rather than on first record, so a misconfigured
// destination fails the command that configured it instead of failing silently
// at the first audited act — the pilot's own finding about an appliance that
// reports it is shipping and is not.
func newSyslogSink(spec, network, address string) (*syslogSink, error) {
	w, err := syslog.Dial(network, address, syslogFacility|syslog.LOG_INFO, syslogTag)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadSinkSpec, spec, err)
	}
	return &syslogSink{spec: spec, w: w}, nil
}

func (s *syslogSink) Name() string { return s.spec }
func (s *syslogSink) Close() error { return s.w.Close() }

// Emit writes one record at LOG_INFO.
//
// syslog.Writer reconnects once on a write error of its own accord, which is
// what makes a TCP destination survive a collector restart without this holding
// any reconnection logic.
func (s *syslogSink) Emit(_ context.Context, _ int64, line []byte) error {
	if err := s.w.Info(string(line)); err != nil {
		return fmt.Errorf("writing to %s: %w", s.spec, err)
	}
	return nil
}

// parseSyslogSpec reads "syslog:", "syslog:tcp://host:514" or
// "syslog:udp://host:514" into arguments for syslog.Dial.
//
// An empty network is the local daemon — a unix socket, or whatever the
// platform's default is — which is the ordinary case and the one that needs no
// configuration at all.
func parseSyslogSpec(spec string) (network, address string, err error) {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(spec, "syslog"), ":"))
	if rest == "" {
		return "", "", nil
	}
	u, err := url.Parse(rest)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s is not a destination: %v", ErrBadSinkSpec, spec, err)
	}
	switch u.Scheme {
	case "tcp", "udp":
	default:
		return "", "", fmt.Errorf("%w: %s names transport %q; want tcp or udp, "+
			"or plain \"syslog:\" for the local daemon", ErrBadSinkSpec, spec, u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("%w: %s names no host", ErrBadSinkSpec, spec)
	}
	// A port is required rather than defaulted to 514. Syslog collectors listen
	// on whatever the site chose, and guessing wrong here fails by delivering
	// nothing to a port nobody reads — which is the failure this whole sink
	// exists to stop.
	if u.Port() == "" {
		return "", "", fmt.Errorf("%w: %s names no port (syslog is conventionally 514, "+
			"but say so)", ErrBadSinkSpec, spec)
	}
	return u.Scheme, u.Host, nil
}
