// Package secret holds the key at /etc/nodary/secret.key and the AEAD helper
// that everything encrypted at rest goes through.
//
// TOTP seeds, the LiteLLM master key and the agent CA private key are all
// sealed under this key (docs/specs/08-data-model.md §4). A backup of the
// database without this file is useless, and the inverse is the real risk: an
// operator who backs up only the database discovers at restore time that every
// agent must re-enroll and every TOTP enrollment must be redone.
//
// Two details here exist because of that asymmetry. Creation is atomic, so a
// crash during a first install cannot leave a truncated key that can never be
// replaced; and every ciphertext carries a key identifier, so the key can be
// rotated incrementally rather than in a single flag-day pass.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nodarynet/nodary/internal/paths"
)

const (
	// keyBytes is 32: AES-256.
	keyBytes = 32
	// keyIDBytes identifies which key sealed a ciphertext. Four bytes of
	// SHA-256 over the key material — enough to tell a handful of keys apart
	// during a rotation, and not a secret.
	keyIDBytes = 4
	// formatVersion prefixes every ciphertext so the construction can change
	// later without guessing at what old blobs are.
	formatVersion = 1
)

var (
	// ErrBadPermissions means the key file is readable by someone other than
	// its owner, or is owned by someone else.
	ErrBadPermissions = errors.New("key file permissions are too permissive")

	// ErrMalformedKey means the file is not exactly 64 lowercase hex digits.
	ErrMalformedKey = errors.New("key file is not 64 hex characters")

	// ErrUnknownKey means a ciphertext was sealed by a key this keyring does
	// not hold — the expected signal during a rotation, and the reason the key
	// id is in the ciphertext at all.
	ErrUnknownKey = errors.New("ciphertext was sealed with an unknown key")

	// ErrBadCiphertext means the blob is truncated, is a format this build does
	// not know, or failed authentication.
	ErrBadCiphertext = errors.New("ciphertext is malformed or has been tampered with")
)

// Key is a keyring: one key that seals, and any number of retired keys that can
// still open.
type Key struct {
	primary aeadKey
	retired []aeadKey
	byID    map[[keyIDBytes]byte]aeadKey
}

type aeadKey struct {
	id   [keyIDBytes]byte
	aead cipher.AEAD
}

// Load reads the key at path, plus any retired keys that should still be able
// to decrypt. Absent retired paths, only the primary key can open a ciphertext.
func Load(path string, retired ...string) (*Key, error) {
	primary, err := readKey(path)
	if err != nil {
		return nil, err
	}
	k := &Key{primary: primary, byID: map[[keyIDBytes]byte]aeadKey{primary.id: primary}}
	for _, p := range retired {
		r, err := readKey(p)
		if err != nil {
			return nil, err
		}
		k.retired = append(k.retired, r)
		k.byID[r.id] = r
	}
	return k, nil
}

// Create generates a key at path if none exists, then loads it.
//
// Creation is a write-then-link rather than an exclusive create. A bare
// O_EXCL create leaves a window in which a crash produces an empty file that
// O_EXCL will then refuse to replace forever — and per
// docs/specs/11-failure-modes.md §5 an unusable key is unrecoverable for
// encrypted material. Writing a temporary file first and linking it into place
// means the key is either absent or complete, and link(2) still fails if the
// target exists, so it keeps the race protection O_EXCL was there for.
func Create(path string) (*Key, error) {
	if k, err := Load(path); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, paths.ModeConfigDir); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	material := make([]byte, keyBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".secret.key.*")
	if err != nil {
		return nil, fmt.Errorf("creating temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the link below has succeeded

	if err := writeAndSync(tmp, hex.EncodeToString(material)+"\n"); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Chmod(paths.ModeSecretKey); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("setting key file mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temporary key file: %w", err)
	}

	if err := os.Link(tmpName, path); err != nil {
		// Losing the race is not a failure: the winner's key is the real one,
		// and ours has never been used for anything.
		if errors.Is(err, os.ErrExist) {
			return Load(path)
		}
		return nil, fmt.Errorf("installing key at %s: %w", path, err)
	}
	// fsync the directory so the new name survives a power cut, not just the
	// bytes it points at.
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	return Load(path)
}

func writeAndSync(f *os.File, s string) error {
	if _, err := f.WriteString(s); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flushing key to disk: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s to sync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", dir, err)
	}
	return nil
}

// readKey opens, validates and decodes one key file.
func readKey(path string) (aeadKey, error) {
	// Every check below is made against the descriptor rather than the path,
	// so nothing can be swapped between the check and the read.
	f, err := openNoFollow(path)
	if err != nil {
		return aeadKey{}, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return aeadKey{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return aeadKey{}, fmt.Errorf("%w: %s is %#o, want %#o",
			ErrBadPermissions, path, perm, paths.ModeSecretKey)
	}
	if err := checkOwner(fi, path); err != nil {
		return aeadKey{}, err
	}

	body, err := readAll(f)
	if err != nil {
		return aeadKey{}, fmt.Errorf("reading %s: %w", path, err)
	}
	material, err := decodeKey(strings.TrimSuffix(string(body), "\n"))
	if err != nil {
		return aeadKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return newAEADKey(material)
}

func readAll(f *os.File) ([]byte, error) {
	// A key file is 65 bytes. Reading a bounded amount means pointing this at
	// something enormous reports a malformed key rather than exhausting memory.
	//
	// An empty file reads as (0, io.EOF) and must not surface as a read error:
	// a zero-length key is exactly what a crash mid-install would leave, and it
	// needs to arrive at the caller as ErrMalformedKey so the message says what
	// is wrong with the file rather than "EOF".
	buf := make([]byte, 128)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

func decodeKey(s string) ([]byte, error) {
	if len(s) != hex.EncodedLen(keyBytes) {
		return nil, fmt.Errorf("%w: it is %d characters", ErrMalformedKey, len(s))
	}
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("%w: it contains uppercase hex", ErrMalformedKey)
	}
	material, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	return material, nil
}

func newAEADKey(material []byte) (aeadKey, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return aeadKey{}, fmt.Errorf("preparing cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return aeadKey{}, fmt.Errorf("preparing GCM: %w", err)
	}
	var id [keyIDBytes]byte
	sum := sha256.Sum256(material)
	copy(id[:], sum[:keyIDBytes])
	return aeadKey{id: id, aead: aead}, nil
}

// ID is the primary key's identifier, as it appears in every ciphertext this
// keyring seals.
func (k *Key) ID() string { return hex.EncodeToString(k.primary.id[:]) }

// Seal encrypts plaintext, binding it to context.
//
// context becomes GCM's additional authenticated data — "totp:user:42". Without
// it, an attacker who can write the database can move user A's encrypted TOTP
// seed into user B's row and it decrypts cleanly. Any identifier used here must
// never be reused: SQLite reuses the rowid of a deleted row under a plain
// INTEGER PRIMARY KEY, so a user id used as context has to be AUTOINCREMENT or
// an opaque string.
//
// Layout: version(1) || keyID(4) || nonce(12) || ciphertext+tag.
func (k *Key) Seal(context string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.primary.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	out := make([]byte, 0, 1+keyIDBytes+len(nonce)+len(plaintext)+k.primary.aead.Overhead())
	out = append(out, formatVersion)
	out = append(out, k.primary.id[:]...)
	out = append(out, nonce...)
	return k.primary.aead.Seal(out, nonce, plaintext, []byte(context)), nil
}

// Open decrypts a ciphertext sealed under the same context.
func (k *Key) Open(context string, ciphertext []byte) ([]byte, error) {
	header := 1 + keyIDBytes
	if len(ciphertext) < header {
		return nil, ErrBadCiphertext
	}
	if ciphertext[0] != formatVersion {
		return nil, fmt.Errorf("%w: format version %d is not supported", ErrBadCiphertext, ciphertext[0])
	}

	var id [keyIDBytes]byte
	copy(id[:], ciphertext[1:header])
	key, ok := k.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: key %s", ErrUnknownKey, hex.EncodeToString(id[:]))
	}

	nonceSize := key.aead.NonceSize()
	if len(ciphertext) < header+nonceSize+key.aead.Overhead() {
		return nil, ErrBadCiphertext
	}
	nonce := ciphertext[header : header+nonceSize]
	plaintext, err := key.aead.Open(nil, nonce, ciphertext[header+nonceSize:], []byte(context))
	if err != nil {
		// Deliberately opaque: a wrong context, a wrong key and a flipped bit
		// are the same event to a caller, and distinguishing them tells an
		// attacker which guess was closer.
		return nil, ErrBadCiphertext
	}
	return plaintext, nil
}
