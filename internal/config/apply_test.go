package config_test

import (
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/store"
)

// TestDeploymentDisabledRoundTrips is R4-36: `nodary model enable`/`disable`
// persists as a field on config.Deployment, so an apply that sets it has to
// survive a read back exactly, the same as every other deployment field does.
func TestDeploymentDisabledRoundTrips(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// A node, written directly: config.Apply's FK check just needs the row to
	// exist, and enrolling one for real is not what this test is about.
	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	defer delivery.Close()
	log := audit.New(db, delivery)
	root := identity.LocalRoot()
	root.Actor.ID = "test"

	apply := func(disabled bool) {
		if _, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
			func(m audit.Mutation) error {
				snap, err := config.Read(ctx, m.Tx())
				if err != nil {
					return err
				}
				snap.Models = append(snap.Models, config.Model{
					ID: "acme/tiny", Backend: "vllm", Source: "local", Artifact: "hf-cache",
				})
				snap.Deployments = []config.Deployment{{
					ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-01", Backend: "vllm",
					GPUs: []int{0}, Disabled: disabled,
				}}
				_, err = config.Apply(ctx, m, time.Now(), snap, config.Options{})
				return err
			}); err != nil {
			t.Fatal(err)
		}
	}

	apply(true)
	snap, err := config.Read(ctx, db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Deployments) != 1 || !snap.Deployments[0].Disabled {
		t.Fatalf("deployments = %+v, want one deployment with Disabled = true", snap.Deployments)
	}

	// And back the other way, through the same ON CONFLICT DO UPDATE path.
	apply(false)
	snap, err = config.Read(ctx, db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Deployments) != 1 || snap.Deployments[0].Disabled {
		t.Fatalf("deployments = %+v, want one deployment with Disabled = false", snap.Deployments)
	}
}
