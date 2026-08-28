package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Status is the outcome of verifying one artifact.
type Status string

const (
	StatusOK          Status = "ok"
	StatusUnreachable Status = "unreachable"
	StatusDigestBad   Status = "digest-mismatch"
	StatusSkipped     Status = "skipped"
)

// Result is one component/platform pair's verification outcome.
type Result struct {
	Component string `json:"component"`
	Platform  string `json:"platform"`
	Status    Status `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// OK reports whether the result is a pass.
func (r Result) OK() bool { return r.Status == StatusOK || r.Status == StatusSkipped }

// VerifyOptions controls how much work Verify does.
type VerifyOptions struct {
	// Platform limits verification to one platform key; empty means all.
	Platform string
	// Offline skips every network call, leaving structural validation only.
	Offline bool
	// Full downloads each artifact and hashes it. Slow and bandwidth-heavy;
	// intended for a nightly CI job rather than every push.
	Full bool
	// Concurrency bounds in-flight requests.
	Concurrency int
	// Timeout applies per artifact.
	Timeout time.Duration
}

func (o *VerifyOptions) setDefaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Timeout <= 0 {
		if o.Full {
			o.Timeout = 10 * time.Minute
		} else {
			o.Timeout = 30 * time.Second
		}
	}
}

// Verify checks that every pinned artifact is reachable and, with Full, that
// its bytes hash to the pinned digest.
//
// Container images are reported as skipped: resolving a registry digest needs
// a registry client and credentials, which R0 does not carry. The manifest's
// structural rules already require every image reference to be digest-pinned,
// so an unpinned image cannot reach this point.
func (m *Manifest) Verify(ctx context.Context, opts VerifyOptions) []Result {
	opts.setDefaults()

	type job struct {
		comp     Component
		platform string
		artifact Artifact
	}
	var jobs []job
	for _, c := range m.Components {
		for plat, a := range c.Platforms {
			if opts.Platform != "" && plat != opts.Platform {
				continue
			}
			jobs = append(jobs, job{comp: c, platform: plat, artifact: a})
		}
	}

	results := make([]Result, len(jobs))
	client := &http.Client{Timeout: opts.Timeout}

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, j := range jobs {
		base := Result{Component: j.comp.Name, Platform: j.platform}

		if j.comp.Kind == KindImage {
			base.Status = StatusSkipped
			base.Detail = "container image; digest pinned in reference"
			results[i] = base
			continue
		}
		if opts.Offline {
			base.Status = StatusSkipped
			base.Detail = "offline"
			results[i] = base
			continue
		}

		wg.Add(1)
		go func(i int, j job, base Result) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = checkArtifact(ctx, client, j.artifact, base, opts.Full)
		}(i, j, base)
	}
	wg.Wait()
	return results
}

func checkArtifact(ctx context.Context, client *http.Client, a Artifact, res Result, full bool) Result {
	method := http.MethodHead
	if full {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, a.URL, nil)
	if err != nil {
		res.Status, res.Detail = StatusUnreachable, err.Error()
		return res
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Status, res.Detail = StatusUnreachable, err.Error()
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Status = StatusUnreachable
		res.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	if !full {
		res.Status = StatusOK
		return res
	}

	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		res.Status, res.Detail = StatusUnreachable, err.Error()
		return res
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != a.SHA256 {
		res.Status = StatusDigestBad
		res.Detail = fmt.Sprintf("want %s, got %s", a.SHA256, got)
		return res
	}
	res.Status = StatusOK
	return res
}
