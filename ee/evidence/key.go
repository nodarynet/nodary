// Package evidence produces the signed bundle of docs/specs/13-evidence.md.
//
// Commercial. See ee/LICENSE.
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/minisign"
	"github.com/nodarynet/nodary/internal/secret"
)

// signingKey is the Ed25519 key this install signs bundles with.
type signingKey struct {
	pub  minisign.PublicKey
	priv ed25519.PrivateKey
}

const keySealLabel = "evidence"

// loadKey reads the install's signing key, creating it on first use.
//
// Creation is a mutation and lands in the chain, which is what makes the key
// trustworthy rather than merely present: the record of its creation sits
// inside the evidence the key later signs, so a substituted key is a key with
// no creation record.
func loadKey(ctx context.Context, m audit.Mutation, k *secret.Key, now time.Time) (signingKey, error) {
	var (
		id, pub string
		sealed  []byte
	)
	err := m.Tx().QueryRowContext(ctx,
		`SELECT key_id, public_key, private_enc FROM evidence_key WHERE singleton = 1`).
		Scan(&id, &pub, &sealed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return createKey(ctx, m, k, now)
	case err != nil:
		return signingKey{}, fmt.Errorf("reading the evidence signing key: %w", err)
	}

	seed, err := k.Open(keySealLabel, id, sealed)
	if err != nil {
		return signingKey{}, fmt.Errorf("opening the evidence signing key: %w", err)
	}
	parsed, err := minisign.ParsePublicKey(pub)
	if err != nil {
		return signingKey{}, fmt.Errorf("reading the stored public key: %w", err)
	}
	return signingKey{pub: parsed, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func createKey(ctx context.Context, m audit.Mutation, k *secret.Key, now time.Time) (signingKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return signingKey{}, fmt.Errorf("generating an evidence signing key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return signingKey{}, fmt.Errorf("generating a key id: %w", err)
	}
	key := signingKey{
		pub:  minisign.PublicKey{ID: raw, Key: priv.Public().(ed25519.PublicKey)},
		priv: priv,
	}
	id := hex.EncodeToString(raw[:])

	// The seed, not the expanded private key: it is what regenerates the key,
	// it is half the size, and it is the form ed25519.NewKeyFromSeed takes back.
	sealed, err := k.Seal(keySealLabel, id, seed)
	if err != nil {
		return signingKey{}, fmt.Errorf("sealing the evidence signing key: %w", err)
	}
	if _, err := m.Tx().ExecContext(ctx,
		`INSERT INTO evidence_key (singleton, key_id, public_key, private_enc, created_at)
		 VALUES (1, ?, ?, ?, ?)`,
		id, minisign.EncodePublicKey(key.pub), sealed,
		now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat),
	); err != nil {
		return signingKey{}, fmt.Errorf("recording the evidence signing key: %w", err)
	}

	// The public half goes in the record. This is the anchor an assessor checks
	// a bundle's key against, so it has to be in the chain and not only in a
	// table that no export carries.
	m.Detail("evidence_key_id", id)
	m.Detail("evidence_public_key", base64.StdEncoding.EncodeToString(key.pub.Key))
	return key, nil
}
