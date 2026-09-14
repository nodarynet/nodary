package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/nodarynet/nodary/internal/api"
)

// ensureImage fetches a control-plane-built image the first time a node needs
// it — docs/specs/04-backends.md §5's "stored in the control plane's mirror and
// served to nodes like any other image".
//
// **Only for an image built here.** A derive is committed into the control
// plane's local content store rather than pushed, so it has no registry a node
// could pull it from; everything else nodary runs is a digest-pinned registry
// reference that `nerdctl run` fetches for itself, and diverting those through
// the mirror would put a hop in front of every deployment to no purpose.
//
// The mirror is the same mTLS surface and the same cache R5-07 already serves
// components from, and `save`/`load` is the same pair the air-gapped bundle
// already moves an image with. Nothing here is a new mechanism.
func (d *Daemon) ensureImage(ctx context.Context, ref string) error {
	if !api.LocalImage(ref) {
		return nil
	}
	if d.imagePresent(ctx, ref) {
		return nil
	}

	// Under the models directory: it is the one place on a GPU host sized for
	// tens of gigabytes, which is what an image this size needs somewhere to
	// land. /tmp on these hosts is routinely a tmpfs.
	dir := orDefault(d.Config.ModelsDir, DefaultModelsDir())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".nodary-image-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	url := strings.TrimRight(d.Config.Server, "/") + api.Prefix +
		"/agent/dist/" + api.DerivedImageFile(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := d.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane's mirror answered %s for %s — `nodary backend "+
			"build` exports one when it builds it", resp.Status, api.DerivedImageFile(ref))
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if out, err := d.Host.Run(ctx, "nerdctl", "load", "-i", tmp.Name()); err != nil {
		return fmt.Errorf("loading %s: %v: %s", ref, err, tail(out))
	}
	// Checked rather than assumed. `load` reports success for a tar it read,
	// and what has to be true is that the digest the deployment pins is now in
	// the store — a mirror serving the wrong file would otherwise be found by
	// `nerdctl run` failing much later.
	if !d.imagePresent(ctx, ref) {
		return fmt.Errorf("%s loaded without leaving %s in the image store",
			api.DerivedImageFile(ref), ref)
	}
	return nil
}

// imagePresent asks the store whether a reference resolves.
//
// `image inspect` for its exit status only, and none of its output: the
// schema is a docker-compatibility surface whose field spellings have moved
// between nerdctl releases, but "did it exit zero" has not.
func (d *Daemon) imagePresent(ctx context.Context, ref string) bool {
	_, err := d.Host.Run(ctx, "nerdctl", "image", "inspect", ref)
	return err == nil
}
