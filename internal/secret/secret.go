// Package secret holds the key at /etc/nodary/secret.key and the AEAD helper
// that everything encrypted at rest goes through.
//
// TOTP seeds, the LiteLLM master key and the agent CA private key are all
// sealed under this key (docs/specs/08-data-model.md §4). A backup of the
// database without this file is useless, and the inverse is the real risk: an
// operator who backs up only the database discovers at restore time that every
// agent must re-enroll and every TOTP enrollment must be redone.
//
// # Construction
//
// Each message gets its own AES-256 key, derived with HKDF-SHA256 from the
// stored key and a 192-bit random salt, and is then sealed with AES-GCM under
// an all-zero nonce. The subkey is unique per message, so the nonce never
// repeats under a given key.
//
// Sealing directly under the stored key with a random 96-bit nonce would be
// simpler, and is what an earlier version did. It carries a call budget: NIST
// SP 800-38D caps random-nonce GCM at 2^32 invocations per key, and a GCM nonce
// repeat is not a partial failure — it leaks the plaintext XOR and the
// authentication subkey, which yields forgery. Nothing in this API signalled
// that budget, and a per-row or per-request caller would eventually have
// reached it. A 192-bit salt moves the collision bound out of reach.
//
// # Wire format
//
//	version(1) || keyID(4) || salt(24) || ciphertext+tag
//
// The version and key id are covered by the AEAD's additional data, so neither
// can be rewritten by an attacker with database write access.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/paths"
)

const (
	// keyBytes is 32: AES-256.
	keyBytes = 32
	// keyIDBytes identifies which key sealed a ciphertext.
	keyIDBytes = 4
	// saltBytes is the per-message HKDF salt. 192 bits puts the birthday bound
	// at 2^96 messages, which removes the call budget as a consideration.
	saltBytes = 24
	// formatVersion prefixes every ciphertext so the construction can change
	// later without guessing at what old blobs are.
	formatVersion = 1

	headerBytes = 1 + keyIDBytes + saltBytes

	// keyIDInfo and subkeyInfo domain-separate the two derivations, so neither
	// value can coincide with a hash of the same material computed elsewhere
	// for another purpose.
	keyIDInfo  = "nodary/secret/keyid/v1"
	subkeyInfo = "nodary/secret/aead/v1"

	// tempPrefix is the name Create writes under before linking into place.
	tempPrefix = ".secret.key."
	// tempMaxAge bounds how long a leftover temporary file is left alone. A
	// crash between creating and linking strands full key material in the
	// configuration directory, and nothing else would ever remove it.
	tempMaxAge = 10 * time.Minute
)

var (
	// ErrBadPermissions means the key file is readable by someone other than
	// its owner, is owned by someone else, or is not a regular file.
	ErrBadPermissions = errors.New("key file permissions are too permissive")

	// ErrMalformedKey means the file is not exactly 64 lowercase hex digits.
	ErrMalformedKey = errors.New("key file is not 64 hex characters")

	// ErrDuplicateKey means two loaded keys share an identifier, which would
	// silently make one of them unreachable.
	ErrDuplicateKey = errors.New("two keys share an identifier")

	// ErrUnknownKey means a ciphertext was sealed by a key this keyring does
	// not hold — the expected signal during a rotation, and the reason the key
	// id is in the ciphertext at all.
	ErrUnknownKey = errors.New("ciphertext was sealed with an unknown key")

	// ErrBadCiphertext means the blob could not be authenticated: a wrong key,
	// a wrong label, or modified bytes. Those are cryptographically
	// indistinguishable, and the wording deliberately stops short of asserting
	// tampering — a mislabelled read during a future data migration would
	// otherwise manufacture tamper alarms in a system built to report them.
	ErrBadCiphertext = errors.New("ciphertext could not be authenticated (wrong key, wrong label, or modified)")
)

// Key is a keyring: one key that seals, and any number of retired keys that can
// still open.
type Key struct {
	primary keyMaterial
	byID    map[[keyIDBytes]byte]keyMaterial
}

type keyMaterial struct {
	id  [keyIDBytes]byte
	raw []byte
}

// Load reads the key at path, plus any retired keys that should still be able
// to decrypt.
func Load(path string, retired ...string) (*Key, error) {
	primary, err := readKey(path)
	if err != nil {
		return nil, err
	}
	k := &Key{primary: primary, byID: map[[keyIDBytes]byte]keyMaterial{primary.id: primary}}
	for _, p := range retired {
		r, err := readKey(p)
		if err != nil {
			return nil, err
		}
		// Overwriting silently would evict the primary from the lookup and make
		// everything sealed under the live key undecryptable — the outcome
		// docs/specs/11-failure-modes.md §5 calls unrecoverable. Four bytes is
		// grindable, so this is a refusal rather than an assumption.
		if _, clash := k.byID[r.id]; clash {
			return nil, fmt.Errorf("%w: %s and %s both have id %s",
				ErrDuplicateKey, path, p, hex.EncodeToString(r.id[:]))
		}
		k.byID[r.id] = r
	}
	return k, nil
}

// Create generates a key at path if none exists, then loads it.
//
// Creation is a write-then-link rather than an exclusive create. A bare O_EXCL
// create leaves a window in which a crash produces an empty file that O_EXCL
// then refuses to replace forever — and per docs/specs/11-failure-modes.md §5
// that is unrecoverable for encrypted material. Writing a temporary file first
// and linking it into place means the key is either absent or complete, and
// link(2) still fails if the target exists, so it keeps the race protection
// O_EXCL was there for.
//
// An existing key that is malformed or badly permissioned is an error, never
// something to overwrite: replacing it would destroy the only means of reading
// everything already encrypted.
func Create(path string) (*Key, error) {
	if k, err := Load(path); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("refusing to replace the existing key at %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, paths.ModeConfigDir); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	material := make([]byte, keyBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	want, err := newKeyMaterial(material)
	if err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("creating temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	linked := false
	defer func() {
		// This is the unlink that drops the temporary name after link(2) has
		// created the second one. It is NOT a no-op after a successful link:
		// without it the directory keeps two names for one inode, and an
		// operator deleting secret.key would not destroy the key material.
		if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "nodary: could not remove %s: %v\n", tmpName, err)
		}
		if linked {
			_ = syncDir(dir) // make the removal durable too
		}
	}()

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
	linked = true
	// fsync the directory so the new name survives a power cut, not just the
	// bytes it points at.
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	sweepStaleTemps(dir, tmpName)

	k, err := Load(path)
	if err != nil {
		return nil, err
	}
	if k.primary.id != want.id {
		return nil, fmt.Errorf("installed key at %s is not the one generated", path)
	}
	return k, nil
}

// sweepStaleTemps removes abandoned temporary key files. A crash between
// CreateTemp and Link strands 64 hex characters of live key material in the
// configuration directory, looking exactly like a key file, and nothing else
// would ever clean it up.
//
// The age bound matters: another process may be midway through its own Create,
// and its temporary file is not ours to remove.
func sweepStaleTemps(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-tempMaxAge)
	for _, e := range entries {
		name := filepath.Join(dir, e.Name())
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) || name == keep {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(name)
	}
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
func readKey(path string) (keyMaterial, error) {
	// Every check below is made against the descriptor rather than the path, so
	// nothing can be swapped between the check and the read. O_NOFOLLOW covers
	// the final component only — parents are resolved normally, which is why
	// the ownership check is the guard that actually matters.
	f, err := openNoFollow(path)
	if err != nil {
		return keyMaterial{}, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return keyMaterial{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	// A FIFO at 0400 owned by the reader passes both checks below, and open(2)
	// on it blocks forever waiting for a writer — a silent, permanent startup
	// hang rather than an error.
	if !fi.Mode().IsRegular() {
		return keyMaterial{}, fmt.Errorf("%w: %s is not a regular file", ErrBadPermissions, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return keyMaterial{}, fmt.Errorf("%w: %s is %#o, want %#o",
			ErrBadPermissions, path, perm, paths.ModeSecretKey)
	}
	if err := checkOwner(fi, path); err != nil {
		return keyMaterial{}, err
	}

	// Sized from the descriptor rather than read speculatively: a single Read
	// returning fewer bytes than the file holds would otherwise be accepted as
	// the whole key, with the remainder silently ignored.
	const encoded = keyBytes * 2 // hex
	if size := fi.Size(); size < encoded || size > encoded+2 {
		return keyMaterial{}, fmt.Errorf("%w: %s is %d bytes", ErrMalformedKey, path, size)
	}
	body := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, body); err != nil {
		return keyMaterial{}, fmt.Errorf("reading %s: %w", path, err)
	}

	// TrimRight rather than TrimSuffix("\n"): a key file that has been through
	// a Windows editor or a hand restore otherwise fails with the misleading
	// "it is 65 characters".
	material, err := decodeKey(strings.TrimRight(string(body), "\r\n"))
	if err != nil {
		return keyMaterial{}, fmt.Errorf("%s: %w", path, err)
	}
	return newKeyMaterial(material)
}

func decodeKey(s string) ([]byte, error) {
	if len(s) != hex.EncodedLen(keyBytes) {
		return nil, fmt.Errorf("%w: it is %d characters", ErrMalformedKey, len(s))
	}
	// Checked in place rather than against strings.ToLower(s), which would
	// leave a second uncleared copy of the key material on the heap.
	for i := range len(s) {
		if c := s[i]; c >= 'A' && c <= 'F' {
			return nil, fmt.Errorf("%w: it contains uppercase hex", ErrMalformedKey)
		}
	}
	material, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	return material, nil
}

func newKeyMaterial(material []byte) (keyMaterial, error) {
	if len(material) != keyBytes {
		return keyMaterial{}, ErrMalformedKey
	}
	sum := sha256.Sum256(append([]byte(keyIDInfo), material...))
	var id [keyIDBytes]byte
	copy(id[:], sum[:keyIDBytes])
	return keyMaterial{id: id, raw: material}, nil
}

// subkey derives this message's AES key. The salt is unique per message, so the
// subkey is too — which is what makes an all-zero GCM nonce safe.
func (k keyMaterial) subkey(salt []byte) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, k.raw, salt, subkeyInfo, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("deriving message key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("preparing cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// ID is the primary key's identifier, as it appears in every ciphertext this
// keyring seals.
func (k *Key) ID() string { return hex.EncodeToString(k.primary.id[:]) }

// Knows reports whether this keyring can open a ciphertext sealed under the
// given key id -- the primary, or any retired key passed to Load.
//
// It is what lets a caller distinguish "sealed under a key we still hold" from
// "sealed under a key that is gone", which are recoverable and unrecoverable
// respectively and otherwise look identical.
func (k *Key) Knows(id string) bool {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != keyIDBytes {
		return false
	}
	var want [keyIDBytes]byte
	copy(want[:], raw)
	_, ok := k.byID[want]
	return ok
}

// additionalData binds a ciphertext to its header and to the row it belongs in.
//
// The label binding is the part that carries weight: without it, an attacker
// who can write the database moves user A's sealed seed into user B's row and
// it decrypts cleanly. kind and id are length-prefixed rather than joined, so
// ("totp", "user:42") and ("totp:user", "42") cannot collide.
//
// Including the header is close to free but does less than it looks. The key id
// and salt are already load-bearing — both feed the subkey derivation, so
// altering either produces a key that cannot decrypt — and the version is
// checked before any decryption happens. Verified: removing the header from
// this function breaks no test, because nothing observable changes today. What
// it does buy is binding the format version, so a future v2 construction under
// the same key cannot be confused with a v1 ciphertext. That is worth the two
// lines while the format is still free to change.
func additionalData(header []byte, kind, id string) []byte {
	aad := make([]byte, 0, len(header)+8+len(kind)+len(id))
	aad = append(aad, header...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(kind)))
	aad = append(aad, kind...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(id)))
	aad = append(aad, id...)
	return aad
}

// Seal encrypts plaintext, binding it to (kind, id) — for example
// ("totp", "usr_7f3a").
//
// Without that binding, an attacker who can write the database can move user
// A's encrypted TOTP seed into user B's row and it decrypts cleanly.
//
// Any id used here must never be reused. SQLite reuses the rowid of a deleted
// row under a plain INTEGER PRIMARY KEY, and docs/specs/07-identity-audit.md §1
// has a deleted user state — so an id must come from an AUTOINCREMENT column or
// be an opaque string.
func (k *Key) Seal(kind, id string, plaintext []byte) ([]byte, error) {
	out := make([]byte, headerBytes, headerBytes+len(plaintext)+16)
	out[0] = formatVersion
	copy(out[1:], k.primary.id[:])
	salt := out[1+keyIDBytes : headerBytes]
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	aead, err := k.primary.subkey(salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize()) // zero: the subkey is per-message
	return aead.Seal(out, nonce, plaintext, additionalData(out[:headerBytes], kind, id)), nil
}

// Open decrypts a ciphertext sealed under the same (kind, id).
func (k *Key) Open(kind, id string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < headerBytes {
		return nil, ErrBadCiphertext
	}
	if ciphertext[0] != formatVersion {
		return nil, fmt.Errorf("%w: format version %d is not supported", ErrBadCiphertext, ciphertext[0])
	}

	var wantID [keyIDBytes]byte
	copy(wantID[:], ciphertext[1:1+keyIDBytes])
	key, ok := k.byID[wantID]
	if !ok {
		return nil, fmt.Errorf("%w: key %s", ErrUnknownKey, hex.EncodeToString(wantID[:]))
	}

	header := ciphertext[:headerBytes]
	aead, err := key.subkey(header[1+keyIDBytes:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, ciphertext[headerBytes:], additionalData(header, kind, id))
	if err != nil {
		return nil, ErrBadCiphertext
	}
	// The header is covered by the AEAD, so a successful Open already proves it
	// was not rewritten. Restating it costs nothing and puts the invariant
	// where a reader will look for it.
	if subtle.ConstantTimeCompare(header[1:1+keyIDBytes], key.id[:]) != 1 {
		return nil, ErrBadCiphertext
	}
	return plaintext, nil
}
