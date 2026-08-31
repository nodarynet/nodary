package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nodarynet/nodary/internal/paths"
)

func newKey(t *testing.T) (*Key, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.key")
	k, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return k, path
}

func TestCreateProducesAReadOnlyOwnerOnlyKey(t *testing.T) {
	_, path := newKey(t)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != paths.ModeSecretKey {
		t.Errorf("mode = %#o, want %#o", got, paths.ModeSecretKey)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(body), "\n")
	if len(s) != 64 {
		t.Errorf("key is %d characters, want 64", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("key is not hex: %v", err)
	}
	if s != strings.ToLower(s) {
		t.Error("key contains uppercase hex")
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	k1, path := newKey(t)
	k2, err := Create(path)
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if k1.ID() != k2.ID() {
		t.Errorf("Create replaced the key: %s then %s", k1.ID(), k2.ID())
	}
}

// Two processes installing at once must agree on one key. A loser that kept its
// own would encrypt under a key nothing else can read.
func TestConcurrentCreateAgreesOnOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	const n = 8
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k, err := Create(path)
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			ids[i] = k.ID()
		}(i)
	}
	wg.Wait()
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("creator %d got key %s, creator 0 got %s", i, id, ids[0])
		}
	}
}

// R1-04's stated done criterion.
func TestTOTPSeedRoundTrips(t *testing.T) {
	k, _ := newKey(t)
	seed := make([]byte, 20) // an RFC 4226 seed
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	sealed, err := k.Seal("totp:user:42", seed)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, seed) {
		t.Error("the plaintext seed appears verbatim in the ciphertext")
	}
	got, err := k.Open("totp:user:42", sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Error("seed did not round-trip")
	}
}

// The other half of R1-04's criterion: a database copied without the key yields
// no plaintext secret.
func TestCiphertextIsUselessWithoutTheKey(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp:user:42", []byte("a totp seed"))
	if err != nil {
		t.Fatal(err)
	}

	// A different install: same code, same database, different key file.
	other, _ := newKey(t)
	if _, err := other.Open("totp:user:42", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("error = %v, want ErrUnknownKey", err)
	}
}

// Without context binding, an attacker able to write the database can move
// user A's encrypted seed into user B's row and it decrypts cleanly.
func TestContextBindingPreventsMovingCiphertext(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp:user:42", []byte("alice's seed"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open("totp:user:43", sealed); !errors.Is(err, ErrBadCiphertext) {
		t.Errorf("a ciphertext moved to another user opened with %v, want a refusal", err)
	}
}

func TestTamperedCiphertextIsRefused(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("ctx", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x01
		if _, err := k.Open("ctx", bad); err == nil {
			t.Fatalf("flipping a bit at offset %d still opened", i)
		}
	}
}

func TestCiphertextCarriesVersionAndKeyID(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("ctx", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != formatVersion {
		t.Errorf("version byte = %d, want %d", sealed[0], formatVersion)
	}
	if got := hex.EncodeToString(sealed[1 : 1+keyIDBytes]); got != k.ID() {
		t.Errorf("key id in ciphertext = %s, want %s", got, k.ID())
	}
}

// Rotation is the reason the key id is in the ciphertext. A retired key must
// still open what it sealed, while new writes use the primary.
func TestRetiredKeyStillOpens(t *testing.T) {
	oldKey, oldPath := newKey(t)
	sealed, err := oldKey.Seal("ctx", []byte("sealed before rotation"))
	if err != nil {
		t.Fatal(err)
	}

	_, newPath := newKey(t)
	ring, err := Load(newPath, oldPath)
	if err != nil {
		t.Fatalf("Load with a retired key: %v", err)
	}
	got, err := ring.Open("ctx", sealed)
	if err != nil {
		t.Fatalf("retired key could not open its own ciphertext: %v", err)
	}
	if string(got) != "sealed before rotation" {
		t.Errorf("got %q", got)
	}
	// New writes must still use the primary.
	fresh, err := ring.Seal("ctx", []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fresh[1 : 1+keyIDBytes]); got == oldKey.ID() {
		t.Error("a new ciphertext was sealed with the retired key")
	}
}

func TestRefusesLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o444, 0o440, 0o404, 0o600 | 0o004} {
		_, path := newKey(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrBadPermissions) {
			t.Errorf("mode %#o: error = %v, want ErrBadPermissions", mode, err)
		}
	}
}

// A symlink would let anyone who can create it redirect the read to a file they
// control.
func TestRefusesASymlink(t *testing.T) {
	_, real := newKey(t)
	link := filepath.Join(t.TempDir(), "secret.key")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Error("a symlinked key file was accepted")
	}
}

func TestRefusesMalformedKeyFiles(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"truncated":     strings.Repeat("a", 63),
		"too long":      strings.Repeat("a", 65),
		"uppercase hex": strings.ToUpper(strings.Repeat("ab", 32)),
		"not hex":       strings.Repeat("z", 64),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret.key")
			if err := os.WriteFile(path, []byte(body), paths.ModeSecretKey); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); !errors.Is(err, ErrMalformedKey) {
				t.Errorf("error = %v, want ErrMalformedKey", err)
			}
		})
	}
}

// A crash between creating and writing the key would, under a bare O_EXCL
// create, leave an empty file that O_EXCL then refuses to replace forever —
// unrecoverable for every secret already encrypted (11 §5). Create must never
// leave a partial key behind under its real name.
func TestCreateLeavesNoPartialKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if _, err := Create(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "secret.key" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only secret.key", names)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("the installed key is not loadable: %v", err)
	}
}

func TestOpenRejectsShortAndUnknownFormats(t *testing.T) {
	k, _ := newKey(t)
	for name, blob := range map[string][]byte{
		"empty":          {},
		"header only":    {formatVersion, 0, 0, 0, 0},
		"future version": append([]byte{formatVersion + 1}, make([]byte, 40)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := k.Open("ctx", blob); err == nil {
				t.Error("accepted a malformed ciphertext")
			}
		})
	}
}
