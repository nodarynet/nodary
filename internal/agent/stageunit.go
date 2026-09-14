package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// R4-30, docs/specs/03-agent.md §5: a weight download runs as a transient unit
// on the host rather than inside the agent process.
//
// Two things come of the move, and the second is the one that made it worth
// doing. The narrow one is that the systemd IP filter genuinely applies here —
// the download is a direct child of the unit, unlike the model unit, where
// §5's own warning is that `IPAddressDeny=` filters `nerdctl` and not the
// container it hands off to. The broader one is that a multi-hour transfer of
// attacker-supplied bytes stops running inside the long-lived root daemon that
// holds this node's mTLS key: the parser it feeds is `crypto/sha256` and
// `net/http`, but the blast radius if either were ever wrong is now a process
// that exits when the download does.

const resolvConfPath = "/etc/resolv.conf"

// enclave is what a weight download has no business reaching, and is the whole
// of the filter's narrowness.
//
// A literal allowlist of the destinations staging *does* need was the obvious
// reading of "narrow" and does not survive contact with how weights are
// served: HuggingFace answers a weight fetch with a redirect to a different
// host entirely, whose addresses are not known until the redirect arrives and
// rotate under short TTLs — and a unit's filter cannot change while it runs,
// so a multi-gigabyte transfer would die mid-flight and look exactly like a
// network outage. Narrowing the other side costs nothing in reach and is
// stable: these ranges are where the control plane, the peer nodes, the rest
// of the customer's network and the cloud metadata service live, and staging
// needs none of them.
//
// 169.254.0.0/16 is the one worth naming individually. It carries
// 169.254.169.254, the instance metadata endpoint, which on a cloud GPU host
// hands out role credentials to anything that can reach it.
var enclave = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"169.254.0.0/16", "127.0.0.0/8",
	"::1/128", "fc00::/7", "fe80::/10",
}

// stageFilter is the unit's IP filter: everything, less the enclave, plus this
// host's own resolvers so that names still resolve.
//
// It leans on one documented systemd rule — the longest matching prefix wins,
// and an allow beats a deny of equal length. So `any` is prefix 0 and loses to
// every entry in enclave, and a resolver at /32 beats the /8 or /16 that
// covers it. TestTheFilterDependsOnLongestPrefixWinning holds that rule in
// place, because the whole filter is wrong in a way nothing else would catch
// if it stopped being true.
func stageFilter(resolvConf string) []string {
	allow := append([]string{"any"}, resolvers(resolvConf)...)
	return []string{
		"--property=IPAddressAllow=" + strings.Join(allow, " "),
		"--property=IPAddressDeny=" + strings.Join(enclave, " "),
	}
}

// resolvers reads the nameservers this host actually uses, each as a
// single-address prefix so it outranks the enclave range containing it.
//
// Read rather than assumed: the stub at 127.0.0.53 is the common case but a
// site resolver on the LAN is ordinary too, and denying the private ranges
// without this would break name resolution on exactly those hosts.
func resolvers(path string) []string {
	// The systemd-resolved stub, which is what an unreadable resolv.conf most
	// often means on a host that has one at all. Narrow on purpose: opening
	// loopback back up would reach a single-box install's own control plane.
	const fallback = "127.0.0.53/32"

	f, err := os.Open(path)
	if err != nil {
		return []string{fallback}
	}
	defer f.Close()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		// The zone goes: a link-local resolver is written fe80::1%eth0 and
		// systemd wants the address alone.
		addr = addr.WithZone("").Unmap()
		one := fmt.Sprintf("%s/%d", addr, addr.BitLen())
		if !seen[one] {
			seen[one] = true
			out = append(out, one)
		}
	}
	if len(out) == 0 {
		return []string{fallback}
	}
	return out
}

// stageUnitName is one model's transient unit.
//
// The hash is not decoration. A model id is an arbitrary string and systemd
// unit names are not, so the readable part is sanitized — which maps `acme/tiny`
// and `acme-tiny` onto the same name. Two models downloading into each other's
// unit is the kind of bug that presents as weights that are inexplicably the
// wrong ones, so the id's own digest settles it.
func stageUnitName(model string) string {
	sum := sha256.Sum256([]byte(model))
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		}
		return '-'
	}, model)
	if len(safe) > 48 {
		safe = safe[:48]
	}
	return "nodary-stage-" + safe + "-" + hex.EncodeToString(sum[:4]) + ".service"
}

// requestPath and progressPath are siblings of the model directory, the same
// place and for the same reason `<dir>.downloading` is one: nothing that looks
// at whether the model directory exists can mistake either for staged weights.
func requestPath(dir string) string  { return dir + ".staging.json" }
func progressPath(dir string) string { return dir + ".progress.json" }

// stageRequest is everything the transient unit needs, which the parent writes
// and the child reads.
//
// A file rather than flags, for one argument: the token. `--setenv=HF_TOKEN=…`
// and a command-line flag are both readable by every local user — in
// `systemctl show` for as long as the unit exists, and in `ps` for as long as
// `systemd-run` runs. This file is 0600, beside weights only root writes.
// The manifest body rides along because it is a file list, not a scalar, and
// has no business on a command line either.
type stageRequest struct {
	Model          string `json:"model"`
	Dir            string `json:"dir"`
	BaseURL        string `json:"base_url"`
	ManifestBody   string `json:"manifest_body"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Token          string `json:"token,omitempty"`
}

func writeStageRequest(path string, req stageRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readStageRequest(path string) (stageRequest, error) {
	var req stageRequest
	b, err := os.ReadFile(path)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return req, fmt.Errorf("reading the staging request: %w", err)
	}
	if req.Model == "" || req.Dir == "" {
		return req, errors.New("the staging request names no model or no directory")
	}
	return req, nil
}

// progress is the child's running verdict, on disk because the parent is a
// different process now and a mutex no longer reaches it.
//
// Written by one goroutine in a process that does nothing else, so it needs no
// lock of its own; the parent only ever reads it.
type progress struct {
	path string
	cur  Stage
}

func (p *progress) set(state string, bytes, total int64, reason string) {
	p.cur.State, p.cur.Bytes, p.cur.Total, p.cur.Reason = state, bytes, total, reason
	// A failure to record progress is not reported anywhere it could be acted
	// on, and does not need to be: the parent falls back to the unit's own
	// liveness and restarts an interrupted download, which is safe because
	// every file already verified on disk is skipped.
	b, err := json.Marshal(p.cur)
	if err != nil {
		return
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, p.path)
}

// readProgress reads what the unit has recorded. Replaced-by-rename above, so
// a read that lands mid-write sees the old file whole rather than half the
// new one.
func readProgress(path string) (Stage, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Stage{}, false
	}
	var s Stage
	if err := json.Unmarshal(b, &s); err != nil || s.State == "" {
		return Stage{}, false
	}
	return s, true
}

// RunStaging downloads one model's weights and exits. This is the child:
// `nodary agent stage --request <path>`, which is all the transient unit runs.
//
// It returns the verdict it recorded rather than an error for a failed
// download, because a download that fails verification is not an error in this
// program — it is docs/specs/05-catalog.md §3's `corrupt`, a terminal state
// with a reason, and the file it wrote is where the agent reads it.
func RunStaging(requestPath string) (Stage, error) {
	req, err := readStageRequest(requestPath)
	if err != nil {
		return Stage{}, err
	}
	dl := &Downloader{BaseURL: req.BaseURL, Token: req.Token, Client: newDownloadClient()}
	p := &progress{path: progressPath(req.Dir), cur: Stage{Model: req.Model, Dir: req.Dir}}
	dl.run(req, p)
	return p.cur, nil
}

// start launches one model's transient unit.
func (dl *Downloader) start(ctx context.Context, req stageRequest) error {
	if dl.Host.Self == "" {
		return errors.New("this agent does not know its own path, so it cannot start a staging unit")
	}
	if err := writeStageRequest(requestPath(req.Dir), req); err != nil {
		return err
	}
	args := []string{
		"--unit=" + stageUnitName(req.Model),
		"--description=nodary staging " + req.Model,
		// Collected the moment it exits, succeeded or failed, so the next
		// reconcile finds either a terminal verdict on disk or a clean slate —
		// never a leftover failed unit object that `systemd-run` refuses to
		// reuse and that nothing would ever clear.
		"--collect",
		"--property=Type=oneshot",
	}
	args = append(args, stageFilter(resolvConfPath)...)
	args = append(args, "--", dl.Host.Self, "agent", "stage", "--request", requestPath(req.Dir))
	if out, err := dl.Host.systemdRun(ctx, args...); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
