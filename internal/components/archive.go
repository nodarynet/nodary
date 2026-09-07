package components

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxArchiveBytes bounds what one tarball may expand to.
//
// A gzip stream can claim to be small and expand without limit, and an install
// that filled the root filesystem would take the host down rather than fail.
// The largest thing nodary ships is containerd at well under 100 MB.
const maxArchiveBytes = 512 << 20

// Extracted is one file placed out of an archive.
type Extracted struct {
	Name string
	Path string
	Mode os.FileMode
}

// Extract unpacks a .tar.gz into dir, keeping only regular files.
//
// The archives here are upstream releases — containerd's, nerdctl's, the CNI
// plugins'. They are digest-verified before they reach this function, so their
// contents are what upstream published; that is a strong guarantee about
// provenance and none at all about shape, so every entry is still checked
// against the rules below.
//
//   - A path that escapes dir is refused. `../../usr/bin/sudo` in a tarball is
//     the oldest trick there is, and a digest pins *which* archive, not what a
//     future release of it contains.
//   - Symlinks and hard links are skipped rather than followed. containerd's
//     tarball has none, and a link is how an extraction reaches outside its
//     directory without any path containing `..`.
//   - Devices, FIFOs and setuid bits are dropped. Nothing nodary installs needs
//     one, and an installer that could create them is a privilege escalation
//     waiting for a supply-chain problem upstream.
func Extract(archive, dir string) ([]Extracted, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", archive, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	var (
		out     []Extracted
		written int64
	)
	tr := tar.NewReader(io.LimitReader(gz, maxArchiveBytes))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("reading %s: %w", archive, err)
		}
		if h.Typeflag != tar.TypeReg {
			// Directories are created as needed below; everything else —
			// symlink, hardlink, device, FIFO — is skipped. See the note above.
			continue
		}

		clean := filepath.Clean(filepath.Join(root, h.Name))
		if !within(root, clean) {
			return out, fmt.Errorf("%s contains %q, which would write outside %s",
				archive, h.Name, dir)
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
			return out, err
		}

		// 0755 or 0644, and never what the archive asked for: the mode bits are
		// attacker-controlled in the general case, and an executable's exact
		// permissions are not information upstream needs to supply.
		mode := os.FileMode(0o644)
		if h.FileInfo().Mode()&0o111 != 0 {
			mode = 0o755
		}
		dst, err := os.OpenFile(clean, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return out, err
		}
		n, err := io.Copy(dst, tr)
		dst.Close()
		if err != nil {
			return out, fmt.Errorf("extracting %s from %s: %w", h.Name, archive, err)
		}
		written += n
		if written > maxArchiveBytes {
			return out, fmt.Errorf("%s expands past %d bytes", archive, int64(maxArchiveBytes))
		}
		out = append(out, Extracted{Name: h.Name, Path: clean, Mode: mode})
	}
	return out, nil
}

// within reports whether path stays inside root once both are cleaned.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
