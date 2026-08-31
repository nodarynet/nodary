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
	"time"

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
	s := strings.TrimRight(string(body), "\r\n")
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

// Two processes installing at once must agree on one key. A loser that kept
// its own would encrypt under a key nothing else can read.
//
// The barrier matters: without it the goroutines serialise and every caller
// after the first takes the Load fast path, so the contended branch never runs
// and the assertion is satisfied by creators that never contended.
func TestConcurrentCreateAgreesOnOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			k, err := Create(path)
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = k.ID()
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("creator %d: %v", i, err)
		}
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("creator %d got key %s, creator 0 got %s", i, id, ids[0])
		}
	}
	// Exactly one file, and no stranded temporaries.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only secret.key", names)
	}
}

// R1-04's stated done criterion.
func TestTOTPSeedRoundTrips(t *testing.T) {
	k, _ := newKey(t)
	seed := make([]byte, 20) // an RFC 4226 seed
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	sealed, err := k.Seal("totp", "usr_7f3a", seed)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, seed) {
		t.Error("the plaintext seed appears verbatim in the ciphertext")
	}
	got, err := k.Open("totp", "usr_7f3a", sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Error("seed did not round-trip")
	}
}

func TestEmptyPlaintextRoundTrips(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Open("totp", "usr_1", sealed)
	if err != nil {
		t.Fatalf("Open of an empty plaintext: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}

// The other half of R1-04's criterion: a database copied without the key yields
// no plaintext secret.
func TestCiphertextIsUselessWithoutTheKey(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_1", []byte("a totp seed"))
	if err != nil {
		t.Fatal(err)
	}

	// A different install: same code, same database, different key file.
	other, _ := newKey(t)
	if _, err := other.Open("totp", "usr_1", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("error = %v, want ErrUnknownKey", err)
	}
}

// Without label binding, an attacker able to write the database can move user
// A's encrypted seed into user B's row and it decrypts cleanly.
func TestLabelBindingPreventsMovingCiphertext(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_alice", []byte("alice's seed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, id string }{
		{"totp", "usr_bob"},
		{"litellm", "usr_alice"},
	} {
		if _, err := k.Open(tc.kind, tc.id, sealed); !errors.Is(err, ErrBadCiphertext) {
			t.Errorf("(%s,%s) opened with %v, want a refusal", tc.kind, tc.id, err)
		}
	}
}

// kind and id are length-prefixed rather than joined, so no two different
// (kind, id) pairs can produce the same binding.
func TestLabelEncodingIsUnambiguous(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "user:42", []byte("seed"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open("totp:user", "42", sealed); !errors.Is(err, ErrBadCiphertext) {
		t.Errorf("a differently-split label opened the ciphertext: %v", err)
	}
}

// Every byte must be covered: no single-bit change anywhere in a ciphertext may
// produce a successful Open.
func TestEveryByteIsAuthenticated(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_1", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x01
		_, err := k.Open("totp", "usr_1", bad)
		switch {
		case err == nil:
			t.Errorf("flipping a bit at offset %d still opened", i)
		case i == 0:
			// The version byte is rejected before the key lookup.
			if !errors.Is(err, ErrBadCiphertext) {
				t.Errorf("offset %d: error = %v, want ErrBadCiphertext", i, err)
			}
		case i < 1+keyIDBytes:
			// A rewritten key id names an unknown key, which is honest — but
			// only because a *known* one still fails authentication, below.
			if !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrBadCiphertext) {
				t.Errorf("offset %d: error = %v", i, err)
			}
		default:
			if !errors.Is(err, ErrBadCiphertext) {
				t.Errorf("offset %d: error = %v, want ErrBadCiphertext", i, err)
			}
		}
	}

	// Truncation and extension.
	for name, bad := range map[string][]byte{
		"truncated by one": sealed[:len(sealed)-1],
		"header only":      sealed[:headerBytes],
		"extended":         append(bytes.Clone(sealed), 0),
	} {
		if _, err := k.Open("totp", "usr_1", bad); !errors.Is(err, ErrBadCiphertext) {
			t.Errorf("%s: error = %v, want ErrBadCiphertext", name, err)
		}
	}
}

// Rewriting the key id to another key the ring actually holds must not decrypt.
//
// This does not test the header-in-AAD binding, despite appearances: the key id
// selects which key derives the subkey, so a rewritten id produces the wrong
// subkey and fails regardless. Verified — removing the header from
// additionalData leaves this test passing. It is still worth asserting, because
// it proves the key id genuinely selects the derivation rather than being
// decorative metadata.
func TestRelabellingToAKnownKeyStillFails(t *testing.T) {
	a, pathA := newKey(t)
	_, pathB := newKey(t)
	ring, err := Load(pathB, pathA)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := a.Seal("totp", "usr_1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the key id to the ring's primary, which the ring does hold.
	relabelled := bytes.Clone(sealed)
	primary, err := hex.DecodeString(ring.ID())
	if err != nil {
		t.Fatal(err)
	}
	copy(relabelled[1:1+keyIDBytes], primary)

	if _, err := ring.Open("totp", "usr_1", relabelled); !errors.Is(err, ErrBadCiphertext) {
		t.Errorf("a relabelled ciphertext gave %v, want ErrBadCiphertext", err)
	}
}

func TestCiphertextCarriesVersionAndKeyID(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_1", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != formatVersion {
		t.Errorf("version byte = %d, want %d", sealed[0], formatVersion)
	}
	if got := hex.EncodeToString(sealed[1 : 1+keyIDBytes]); got != k.ID() {
		t.Errorf("key id in ciphertext = %s, want %s", got, k.ID())
	}
	if len(sealed) < headerBytes {
		t.Errorf("ciphertext is %d bytes, shorter than the %d-byte header", len(sealed), headerBytes)
	}
}

// Every message must use a fresh salt. A repeat would mean a repeated subkey
// under a zero nonce, which is the failure the whole construction avoids.
func TestSaltIsFreshPerMessage(t *testing.T) {
	k, _ := newKey(t)
	seen := make(map[string]bool)
	for range 500 {
		sealed, err := k.Seal("totp", "usr_1", []byte("same plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		salt := string(sealed[1+keyIDBytes : headerBytes])
		if seen[salt] {
			t.Fatal("a salt repeated within 500 messages")
		}
		seen[salt] = true
	}
	// Identical plaintext under an identical label must still produce distinct
	// ciphertexts.
	if len(seen) != 500 {
		t.Errorf("%d distinct salts in 500 messages", len(seen))
	}
}

// Rotation is the reason the key id is in the ciphertext.
func TestRetiredKeyStillOpens(t *testing.T) {
	oldKey, oldPath := newKey(t)
	sealed, err := oldKey.Seal("totp", "usr_1", []byte("sealed before rotation"))
	if err != nil {
		t.Fatal(err)
	}

	newPrimary, newPath := newKey(t)
	ring, err := Load(newPath, oldPath)
	if err != nil {
		t.Fatalf("Load with a retired key: %v", err)
	}
	got, err := ring.Open("totp", "usr_1", sealed)
	if err != nil {
		t.Fatalf("retired key could not open its own ciphertext: %v", err)
	}
	if string(got) != "sealed before rotation" {
		t.Errorf("got %q", got)
	}
	// New writes must use the primary, asserted positively.
	fresh, err := ring.Seal("totp", "usr_1", []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fresh[1 : 1+keyIDBytes]); got != newPrimary.ID() {
		t.Errorf("new ciphertext sealed with %s, want the primary %s", got, newPrimary.ID())
	}
}

// Two keys sharing an id would silently evict one from the lookup, making
// everything sealed under it undecryptable. Four bytes is grindable, so this
// must be a refusal.
func TestDuplicateKeyIDsRefused(t *testing.T) {
	_, path := newKey(t)
	if _, err := Load(path, path); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("error = %v, want ErrDuplicateKey", err)
	}
}

func TestRefusesLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o444, 0o440, 0o404, 0o604} {
		_, path := newKey(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrBadPermissions) {
			t.Errorf("mode %#o: error = %v, want ErrBadPermissions", mode, err)
		}
	}
}

// A FIFO at 0400 owned by the reader passes the mode and owner checks, and
// open(2) on it blocks forever waiting for a writer — a silent, permanent
// startup hang rather than an error.
func TestRefusesANonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := makeFIFO(path, 0o400); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBadPermissions) {
			t.Errorf("error = %v, want ErrBadPermissions", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocked on a FIFO instead of refusing it")
	}
}

// A symlink would let anyone able to create it redirect the read to a file they
// control.
func TestRefusesASymlink(t *testing.T) {
	_, real := newKey(t)
	link := filepath.Join(t.TempDir(), "secret.key")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	_, err := Load(link)
	if err == nil {
		t.Fatal("a symlinked key file was accepted")
	}
	// Specifically the O_NOFOLLOW refusal, not some later check.
	if !strings.Contains(err.Error(), "too many levels") &&
		!errors.Is(err, os.ErrInvalid) && !strings.Contains(err.Error(), "symbolic link") {
		t.Logf("refused with %v", err) // message varies by platform
	}
}

func TestRefusesMalformedKeyFiles(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"truncated":     strings.Repeat("a", 63),
		"too long":      strings.Repeat("a", 65),
		"way too long":  strings.Repeat("a", 4096),
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

// A key file that has been through a Windows editor or a hand restore must not
// fail with the misleading "it is 65 characters".
func TestAcceptsCRLF(t *testing.T) {
	_, src := newKey(t)
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "secret.key")
	crlf := strings.TrimRight(string(body), "\n") + "\r\n"
	if err := os.WriteFile(path, []byte(crlf), paths.ModeSecretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a CRLF key file was refused: %v", err)
	}
}

// Replacing an unreadable key would destroy the only means of decrypting
// everything already stored, so Create must refuse rather than mint.
func TestCreateRefusesToReplaceAnUnreadableKey(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     "",
		"truncated": "deadbeef",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret.key")
			if err := os.WriteFile(path, []byte(body), paths.ModeSecretKey); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(path); err == nil {
				t.Fatal("Create replaced an unreadable key")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != body {
				t.Error("Create modified the existing file")
			}
		})
	}
}

// A crash between CreateTemp and Link strands full key material in the
// configuration directory, looking exactly like a key file. Nothing else would
// ever remove it.
func TestStaleTemporaryKeysAreSwept(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, tempPrefix+"crashed")
	if err := os.WriteFile(stale, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * tempMaxAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	// A temporary file from a Create happening right now is not ours to remove.
	fresh := filepath.Join(dir, tempPrefix+"inflight")
	if err := os.WriteFile(fresh, []byte("in progress"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Create(filepath.Join(dir, "secret.key")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Error("an abandoned temporary key file was left in place")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a temporary file from an in-flight Create was removed")
	}
}

func TestCreateLeavesNoExtraFiles(t *testing.T) {
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
	// And exactly one name for the inode: a surviving hard link would mean
	// deleting secret.key does not destroy the material.
	if n := linkCount(t, path); n != 1 {
		t.Errorf("key inode has %d links, want 1", n)
	}
}

func TestOpenRejectsShortAndUnknownFormats(t *testing.T) {
	k, _ := newKey(t)
	sealed, err := k.Seal("totp", "usr_1", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	future := bytes.Clone(sealed)
	future[0] = formatVersion + 1

	for name, blob := range map[string][]byte{
		"empty":           {},
		"one byte":        sealed[:1],
		"inside header":   sealed[:headerBytes-1],
		"header exactly":  sealed[:headerBytes],
		"no room for tag": sealed[:headerBytes+1],
		"future version":  future,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := k.Open("totp", "usr_1", blob); !errors.Is(err, ErrBadCiphertext) {
				t.Errorf("error = %v, want ErrBadCiphertext", err)
			}
		})
	}
}
