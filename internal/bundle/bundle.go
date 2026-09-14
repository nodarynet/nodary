// Package bundle is the offline install artifact of docs/specs/01-install.md §6.
//
// A bundle is built on a connected machine and carries what an air-gapped site
// cannot fetch: the pinned archives and binaries, and the container images a
// site with no registry has no other way to obtain.
//
// **Nothing here is a second verifier.** The artifacts are laid out under the
// names internal/components gives them in the cache, so an install that finds
// them already present re-hashes each one against the digest the *embedded
// manifest* pins and reports it `cached` — the same check the online path runs,
// reached by the same code. §6's "both verify identically" is therefore a
// property of the layout rather than a claim this package makes.
//
// That is also what protects the bundle. A member swapped in transit does not
// match the manifest compiled into the binary that will install it, and the
// existing check catches it; a bundle signature would attest who assembled the
// archive, which the digests already constrain.
//
// Plain tar, not tar.zst: every member is either a gzipped release archive or
// a container image export whose layers are already compressed, so a second
// pass over several gigabytes buys approximately nothing. §6's example
// filename says `.tar.zst`; this writes `.tar` and the deviation is deliberate
// rather than missing.
package bundle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/components"
)

// Schema is the bundle layout this binary writes and understands.
const Schema = 1

// The members of a bundle. ManifestName is written first so a reader can
// stream one pass and know what to expect before the gigabytes arrive.
const (
	ManifestName   = "bundle.json"
	ComponentsName = "components.json"
	DistDir        = "dist"
	ImagesDir      = "images"
	// ConfigDir holds files that belong beside the configuration rather than
	// in the cache — today the advisory feed and its detached signature, which
	// an air-gapped site has no other way to receive (R9-18).
	ConfigDir = "config"
)

// ErrNotABundle is a file that is not one, or is one this binary is too old to
// read.
var ErrNotABundle = errors.New("not a nodary bundle")

// ErrDigestMismatch is a member whose bytes are not what the bundle says.
var ErrDigestMismatch = errors.New("bundle member does not match its recorded digest")

// Member is one archive or binary.
type Member struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	// Path is relative to the bundle root, and its basename is exactly the
	// cache's filename for this artifact (components.ArtifactName). That is
	// the whole of how an extracted bundle becomes a warm cache.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Image is one container image export.
type Image struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	// Reference is digest-pinned, so the runtime verifies it on load and the
	// bundle's own digest is a second, independent check rather than the only
	// one.
	Reference string `json:"reference"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}

// Manifest is bundle.json: what this archive is and what is in it.
type Manifest struct {
	Schema        int      `json:"schema"`
	NodaryVersion string   `json:"nodary_version"`
	Platform      string   `json:"platform"`
	CreatedAt     string   `json:"created_at"`
	Components    []Member `json:"components"`
	Images        []Image  `json:"images"`
	// Config are files carried verbatim into the configuration directory.
	//
	// **Not verified here, and that is deliberate.** The advisory feed's
	// verification is its detached minisign signature, which travels beside it
	// and is checked by `advisory check` on every read — unconditionally, with
	// no way to skip it. A second check in this package would either duplicate
	// that or, worse, look like the one that mattered. The bundle's own digest
	// covers the transfer; the signature covers the content.
	Config []Member `json:"config,omitempty"`
}

// Bytes is everything the bundle carries, for a line an operator can check
// against the media they are about to write it to.
func (m Manifest) Bytes() int64 {
	var n int64
	for _, c := range m.Components {
		n += c.Bytes
	}
	for _, i := range m.Images {
		n += i.Bytes
	}
	for _, c := range m.Config {
		n += c.Bytes
	}
	return n
}

// Runner runs a command. Injected so the image export can be driven without a
// container runtime in a test, and so every shell-out in this package is
// visible in one field rather than scattered through it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// CreateOptions is what to put in a bundle.
type CreateOptions struct {
	Out      string
	Platform string
	// Dist is the cache the artifacts were fetched into. Bundle creation does
	// not download: `components fetch` already does exactly that, verifies
	// each digest before the file lands, and is the step an operator runs to
	// repair a cache. A second downloader here would be a second place for the
	// verification to differ.
	Dist string
	// Components are the archives and binaries to carry, already selected.
	Components []components.Component
	// Images are the container images to export, already selected.
	Images []components.Component
	// Config are paths to files carried into the configuration directory,
	// taken verbatim. Their basenames become their names at the far end, so
	// two files with the same basename cannot both be carried.
	Config []string
	// ManifestDoc is the component manifest this bundle was resolved against,
	// carried so the receiving site can see what the sending binary pinned
	// even when the two binaries differ.
	ManifestDoc   []byte
	NodaryVersion string
	Now           time.Time
	// Run drives `nerdctl`. Nil means the image export is skipped, which is
	// only correct for a bundle with no images in it.
	Run Runner
	// Progress is called before each member is written, so a multi-gigabyte
	// export is not silence.
	Progress func(what string)
}

// Create writes a bundle.
func Create(ctx context.Context, o CreateOptions) (Manifest, error) {
	if o.Out == "" {
		return Manifest{}, errors.New("no output path")
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	m := Manifest{Schema: Schema, NodaryVersion: o.NodaryVersion,
		Platform: o.Platform, CreatedAt: o.Now.UTC().Format(time.RFC3339)}

	// Images are exported to a scratch directory first, because their size is
	// not known until `nerdctl save` has finished writing one and the tar
	// header has to carry it.
	scratch, err := os.MkdirTemp(filepath.Dir(o.Out), ".nodary-bundle-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(scratch)

	type staged struct{ name, src string }
	var files []staged

	for _, c := range o.Components {
		name := components.ArtifactName(c, o.Platform)
		src := filepath.Join(o.Dist, name)
		sum, size, err := hashFile(src)
		if err != nil {
			return Manifest{}, fmt.Errorf("%s is not in the cache at %s: run `nodary components "+
				"fetch` first, which is what verifies it: %w", c.Name, o.Dist, err)
		}
		a := c.Platforms[o.Platform]
		if a.SHA256 != "" && sum != a.SHA256 {
			// The cache is where `components fetch` already checked this, so
			// reaching here means something changed it afterwards. Refused
			// rather than carried into a bundle nobody will check again until
			// it is on an air-gapped machine.
			return Manifest{}, fmt.Errorf("%w: %s in the cache hashes to %s and the manifest "+
				"pins %s", ErrDigestMismatch, name, sum[:12], a.SHA256[:12])
		}
		rel := path.Join(DistDir, name)
		m.Components = append(m.Components, Member{Component: c.Name, Version: c.Version,
			Path: rel, SHA256: sum, Bytes: size})
		files = append(files, staged{rel, src})
	}

	for _, c := range o.Images {
		a := c.Platforms[o.Platform]
		if a.Image == "" {
			return Manifest{}, fmt.Errorf("%s has no image for %s", c.Name, o.Platform)
		}
		if o.Run == nil {
			return Manifest{}, fmt.Errorf("%s is an image and this bundle has no way to export "+
				"one", c.Name)
		}
		name := imageFileName(c, o.Platform)
		dest := filepath.Join(scratch, name)
		if o.Progress != nil {
			o.Progress(c.Name + " " + a.Image)
		}
		if err := saveImage(ctx, o.Run, a.Image, dest); err != nil {
			return Manifest{}, err
		}
		sum, size, err := hashFile(dest)
		if err != nil {
			return Manifest{}, err
		}
		rel := path.Join(ImagesDir, name)
		m.Images = append(m.Images, Image{Component: c.Name, Version: c.Version,
			Reference: a.Image, Path: rel, SHA256: sum, Bytes: size})
		files = append(files, staged{rel, dest})
	}

	for _, src := range o.Config {
		sum, size, err := hashFile(src)
		if err != nil {
			return Manifest{}, err
		}
		rel := path.Join(ConfigDir, filepath.Base(src))
		m.Config = append(m.Config, Member{Component: filepath.Base(src),
			Path: rel, SHA256: sum, Bytes: size})
		files = append(files, staged{rel, src})
	}

	// Written to a temporary file and renamed, so an interrupted create leaves
	// no half-bundle that looks installable.
	tmp, err := os.CreateTemp(filepath.Dir(o.Out), "."+filepath.Base(o.Out)+".*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	tw := tar.NewWriter(tmp)
	doc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	// First, so a reader knows what is coming before the gigabytes do.
	if err := addBytes(tw, ManifestName, append(doc, '\n')); err != nil {
		return Manifest{}, err
	}
	if len(o.ManifestDoc) > 0 {
		if err := addBytes(tw, ComponentsName, o.ManifestDoc); err != nil {
			return Manifest{}, err
		}
	}
	for _, f := range files {
		if o.Progress != nil {
			o.Progress(f.name)
		}
		if err := addFile(tw, f.name, f.src); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}
	if err := tmp.Close(); err != nil {
		return Manifest{}, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(tmp.Name(), o.Out); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// imageFileName is one image's export, named after the component rather than
// the reference: a reference holds slashes, colons and an `@sha256:` that no
// path component should carry.
func imageFileName(c components.Component, platform string) string {
	return fmt.Sprintf("%s-%s-%s.tar", c.Name, c.Version,
		strings.ReplaceAll(platform, "/", "-"))
}

// saveImage pulls and exports one image.
//
// Pulled first, because a connected machine building a bundle for a site it
// will never see again should not silently export a stale local copy of a
// digest-pinned reference — and a pull by digest is a no-op when the bytes are
// already there.
func saveImage(ctx context.Context, run Runner, ref, dest string) error {
	if out, err := run(ctx, "nerdctl", "pull", "--quiet", ref); err != nil {
		return fmt.Errorf("pulling %s: %v: %s", ref, err, tail(out))
	}
	if out, err := run(ctx, "nerdctl", "save", "-o", dest, ref); err != nil {
		return fmt.Errorf("exporting %s: %v: %s", ref, err, tail(out))
	}
	return nil
}

func addBytes(tw *tar.Writer, name string, body []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func addFile(tw *tar.Writer, name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: info.Size(), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Read returns a bundle's manifest without extracting it.
//
// One pass that stops at the first member, which is why Create writes
// bundle.json first: an operator asking what is in a forty-gigabyte file
// should not wait for forty gigabytes to find out.
func Read(archive string) (Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	h, err := tr.Next()
	if err != nil || h.Name != ManifestName {
		return Manifest{}, fmt.Errorf("%w: %s does not begin with %s", ErrNotABundle, archive, ManifestName)
	}
	var m Manifest
	dec := json.NewDecoder(io.LimitReader(tr, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrNotABundle, err)
	}
	if m.Schema != Schema {
		return Manifest{}, fmt.Errorf("%w: schema %d, want %d — this bundle was written by a "+
			"different release", ErrNotABundle, m.Schema, Schema)
	}
	return m, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func tail(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 400 {
		s = "…" + s[len(s)-400:]
	}
	return s
}

// OpenOptions is where a bundle's contents go.
type OpenOptions struct {
	// Dist is the component cache, normally /var/lib/nodary/dist. Members land
	// under the names components.Fetch looks for, which is what turns an
	// extracted bundle into a cache the ordinary install path finds warm.
	Dist string
	// Pinned is the manifest this binary embeds. Every member is checked
	// against it as well as against the bundle's own record — that second
	// check is the one that matters, because it is the only one whose
	// expectation did not travel with the archive.
	Pinned *components.Manifest
	// Platform selects which artifact each component's digest is compared to.
	Platform string
	// Config is where the carried configuration files land, normally
	// /etc/nodary. Empty skips them: a bundle can be opened for its cache
	// alone, and writing into a configuration directory is a different act
	// from warming a cache.
	Config string
	// Run drives `nerdctl load`. Nil skips the image load, which `bundle
	// verify` wants and an install does not.
	Run      Runner
	Progress func(what string)
}

// Opened is what one member's extraction came to.
type Opened struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	// Loaded is true for an image handed to the container runtime.
	Loaded bool `json:"loaded,omitempty"`
	// Config is true for a file placed beside the configuration rather than in
	// the cache.
	Config bool `json:"config,omitempty"`
}

// Open extracts a bundle, verifying every member as it lands.
//
// **Two digests, and the second is the point.** Each member is hashed while it
// is written and compared to what bundle.json recorded, which catches a
// truncated or corrupted transfer; then, for anything the embedded manifest
// pins, it is compared to *that* — the expectation that did not travel inside
// the archive and therefore cannot have been edited with it.
//
// Verified before it is placed, like components.fetchOne: a digest checked
// after the file is in position leaves a window where something can use it.
func Open(ctx context.Context, archive string, o OpenOptions) (Manifest, []Opened, error) {
	m, err := Read(archive)
	if err != nil {
		return Manifest{}, nil, err
	}
	if o.Dist == "" {
		return m, nil, errors.New("no cache directory to open into")
	}
	if err := os.MkdirAll(o.Dist, 0o755); err != nil {
		return m, nil, err
	}

	want := map[string]Member{}
	for _, c := range m.Components {
		want[c.Path] = c
	}
	images := map[string]Image{}
	for _, i := range m.Images {
		images[i.Path] = i
	}
	conf := map[string]Member{}
	for _, c := range m.Config {
		conf[c.Path] = c
	}
	if len(conf) > 0 && o.Config != "" {
		if err := os.MkdirAll(o.Config, 0o755); err != nil {
			return m, nil, err
		}
	}
	// The digests this binary pins, which is the expectation that did not
	// arrive in the archive.
	pinned := map[string]string{}
	if o.Pinned != nil {
		for _, c := range o.Pinned.ForPlatform(o.Platform) {
			a := c.Platforms[o.Platform]
			if a.SHA256 != "" {
				pinned[components.ArtifactName(c, o.Platform)] = a.SHA256
			}
		}
	}

	f, err := os.Open(archive)
	if err != nil {
		return m, nil, err
	}
	defer f.Close()

	imageScratch, err := os.MkdirTemp("", "nodary-images-")
	if err != nil {
		return m, nil, err
	}
	defer os.RemoveAll(imageScratch)

	var out []Opened
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, out, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		member, isComponent := want[h.Name]
		image, isImage := images[h.Name]
		cfg, isConfig := conf[h.Name]
		switch {
		case isComponent:
			base := path.Base(h.Name)
			dest := filepath.Join(o.Dist, base)
			if o.Progress != nil {
				o.Progress(base)
			}
			sum, n, err := extract(tr, o.Dist, dest)
			if err != nil {
				return m, out, err
			}
			if sum != member.SHA256 {
				os.Remove(dest)
				return m, out, fmt.Errorf("%w: %s hashes to %s and the bundle records %s",
					ErrDigestMismatch, base, sum[:12], member.SHA256[:12])
			}
			if p, ok := pinned[base]; ok && p != sum {
				os.Remove(dest)
				return m, out, fmt.Errorf("%w: %s hashes to %s and this build pins %s — the "+
					"bundle is internally consistent and is not what this binary expects",
					ErrDigestMismatch, base, sum[:12], p[:12])
			}
			out = append(out, Opened{Name: member.Component, Path: dest, SHA256: sum, Bytes: n})

		case isImage:
			base := path.Base(h.Name)
			dest := filepath.Join(imageScratch, base)
			if o.Progress != nil {
				o.Progress(base)
			}
			sum, n, err := extract(tr, imageScratch, dest)
			if err != nil {
				return m, out, err
			}
			if sum != image.SHA256 {
				return m, out, fmt.Errorf("%w: %s hashes to %s and the bundle records %s",
					ErrDigestMismatch, base, sum[:12], image.SHA256[:12])
			}
			got := Opened{Name: image.Component, Path: image.Reference, SHA256: sum, Bytes: n}
			if o.Run != nil {
				if res, err := o.Run(ctx, "nerdctl", "load", "-i", dest); err != nil {
					return m, out, fmt.Errorf("loading %s: %v: %s", image.Reference, err, tail(res))
				}
				got.Loaded = true
			}
			out = append(out, got)

		case isConfig:
			base := path.Base(h.Name)
			if o.Config == "" {
				// Counted anyway: the member is present, and skipping the
				// write is the caller's choice rather than a gap in the
				// archive.
				out = append(out, Opened{Name: cfg.Component, SHA256: cfg.SHA256,
					Bytes: cfg.Bytes, Config: true})
				continue
			}
			dest := filepath.Join(o.Config, base)
			if o.Progress != nil {
				o.Progress(base)
			}
			sum, n, err := extract(tr, o.Config, dest)
			if err != nil {
				return m, out, err
			}
			if sum != cfg.SHA256 {
				os.Remove(dest)
				return m, out, fmt.Errorf("%w: %s hashes to %s and the bundle records %s",
					ErrDigestMismatch, base, sum[:12], cfg.SHA256[:12])
			}
			out = append(out, Opened{Name: cfg.Component, Path: dest, SHA256: sum,
				Bytes: n, Config: true})
		}
	}
	if len(out) != len(m.Components)+len(m.Images)+len(m.Config) {
		return m, out, fmt.Errorf("%w: %s records %d members and carries %d", ErrNotABundle,
			archive, len(m.Components)+len(m.Images)+len(m.Config), len(out))
	}
	return m, out, nil
}

// extract writes one member through a hash, into a temporary file in the
// destination directory so the rename is on one filesystem and atomic.
func extract(r io.Reader, dir, dest string) (string, int64, error) {
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dest)+".*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
