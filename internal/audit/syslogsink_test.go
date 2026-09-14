package audit

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A site with no SIEM has syslog, and pointing this at the wrong place has to
// fail where somebody can see it. Every form is pinned, because a destination
// that parses to something slightly different from what was written is the
// failure this sink exists to prevent: an appliance that reports it is shipping
// records and is not.
func TestSyslogSpecFormsAreExactlyThese(t *testing.T) {
	for _, c := range []struct {
		spec          string
		network, addr string
		wantErr       bool
	}{
		{spec: "syslog", network: "", addr: ""},
		{spec: "syslog:", network: "", addr: ""},
		{spec: "syslog:tcp://collector.internal:514", network: "tcp", addr: "collector.internal:514"},
		{spec: "syslog:udp://10.0.0.4:1514", network: "udp", addr: "10.0.0.4:1514"},
		// A space after the colon is natural in a systemd Environment= line,
		// and used to land inside the value — the same trap FileSink records.
		{spec: "syslog: tcp://host:514", network: "tcp", addr: "host:514"},

		// A port is not defaulted to 514: collectors listen where the site put
		// them, and guessing wrong delivers nothing to a port nobody reads.
		{spec: "syslog:tcp://collector.internal", wantErr: true},
		{spec: "syslog:https://collector.internal:514", wantErr: true},
		{spec: "syslog:tcp://", wantErr: true},
	} {
		network, addr, err := parseSyslogSpec(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q was accepted as %q/%q", c.spec, network, addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if network != c.network || addr != c.addr {
			t.Errorf("%q -> %q/%q, want %q/%q", c.spec, network, addr, c.network, c.addr)
		}
	}
}

// End to end against a listener, because every hop between a parsed spec and a
// byte on a socket is the kind that looks wired and turns out never to have
// carried anything.
func TestTheSyslogSinkDeliversTheRecordAsItStands(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	lines := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				lines <- line
			}
			if err != nil {
				return
			}
		}
	}()

	sinks, err := ParseSinks("syslog:tcp://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(sinks) != 1 {
		t.Fatalf("sinks = %d, want one", len(sinks))
	}
	defer sinks[0].Close()

	record := `{"action":"user.add","seq":7}`
	if err := sinks[0].Emit(context.Background(), 7, []byte(record)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-lines:
		// The record arrives unmodified, so a JSON-aware collector can parse
		// it. A sequence prefix would survive truncation better and would stop
		// every such collector reading any of it.
		if !strings.Contains(got, record) {
			t.Errorf("the record did not arrive intact: %q", got)
		}
		// Tagged, so a collector can select nodary's records without matching
		// on their content.
		if !strings.Contains(got, syslogTag) {
			t.Errorf("no %s tag in %q", syslogTag, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived at the collector")
	}
}

// Dialed when it is configured, not at the first audited act. A destination
// that is wrong has to fail the command that set it — an appliance configured
// to ship its chain and quietly not doing so is the failure mode the whole
// delivery posture exists for.
func TestAnUnreachableSyslogDestinationFailsWhenItIsConfigured(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening there now

	sinks, err := ParseSinks("syslog:tcp://" + addr)
	if err == nil {
		for _, s := range sinks {
			s.Close()
		}
		t.Fatal("a destination with nothing listening was accepted")
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("the error does not name the destination: %v", err)
	}
}
