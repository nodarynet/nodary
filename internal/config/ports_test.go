package config_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/store"
)

// applier is a database with two approved nodes and a model, and a function
// that applies a snapshot through the audited path the way both front ends do.
func applier(t *testing.T) func(...config.Deployment) error {
	t.Helper()
	return applierFor(t, config.Model{
		ID: "acme/tiny", Backend: "vllm", Source: "local", Artifact: "hf-cache"})
}

// applierFor is the same thing with the catalog spelled out, for the checks
// that are about the model rather than about the deployment.
func applierFor(t *testing.T, models ...config.Model) func(...config.Deployment) error {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		// The offer is what R6-16 reads the node's silicon out of. gpu-01 and
		// gpu-02 offer NVIDIA cards because that is what every deployment in
		// these tests is placed on; gpu-amd is here so one test can place a
		// backend on silicon it does not run on.
		for n, offer := range map[string]string{
			"gpu-01":  `{"gpus":[{"index":0},{"index":1}]}`,
			"gpu-02":  `{"gpus":[{"index":0},{"index":1}]}`,
			"gpu-amd": `{"gpus":[{"index":0,"vendor":"amd"}]}`,
			// Enrolled, approved, and has never reported. Its silicon is not
			// yet a fact about anything.
			"gpu-new": ``,
		} {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO node (name, state, offer_json, created_at) VALUES (?, 'approved', ?, ?)`,
				n, offer, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)
	root := identity.LocalRoot()
	root.Actor.ID = "test"

	return func(deployments ...config.Deployment) error {
		_, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
			func(m audit.Mutation) error {
				snap, err := config.Read(ctx, m.Tx())
				if err != nil {
					return err
				}
				snap.Models = models
				snap.Deployments = deployments
				_, err = config.Apply(ctx, m, time.Now(), snap, config.Options{})
				return err
			})
		return err
	}
}

func dep(id, node string, gpu, port int) config.Deployment {
	return config.Deployment{ID: id, ModelID: "acme/tiny", NodeName: node,
		Backend: "vllm", GPUs: []int{gpu}, Port: port}
}

// Two deployments on one node publishing the same loopback port is not a loud
// failure: the second container never binds, the first keeps serving, and the
// gateway's route for the second model reaches the first model's server — a
// request for one model answered by another and metered against the wrong one.
// `model register` defaults --port to 8001, so this was the ordinary result of
// registering a second model on a node.
func TestTwoDeploymentsMayNotPublishOnePortOnOneNode(t *testing.T) {
	apply := applier(t)
	err := apply(dep("dep_one", "gpu-01", 0, 8001), dep("dep_two", "gpu-01", 1, 8001))
	if err == nil {
		t.Fatal("two deployments took one port on one node")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("err = %v, want it recognizable as a bad document (a 500 tells the caller nothing)", err)
	}
	// It has to name both, because the operator is about to go and change one.
	for _, want := range []string{"dep_one", "dep_two", "8001", "gpu-01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}

// A port is published on 127.0.0.1, so it is only ever in contention on one
// machine. Two nodes each serving on 8001 is the ordinary fleet.
func TestOnePortOnTwoNodesIsFine(t *testing.T) {
	apply := applier(t)
	if err := apply(dep("dep_one", "gpu-01", 0, 8001), dep("dep_two", "gpu-02", 0, 8001)); err != nil {
		t.Errorf("two nodes may each publish 8001: %v", err)
	}
}

// The check runs after the writes rather than before each one, so two
// deployments *exchanging* ports in one document applies. Checking before each
// insert would refuse it for a collision that exists only halfway through the
// loop — a false refusal is worse than no check, because it blocks work that
// is correct.
func TestTwoDeploymentsMayExchangePorts(t *testing.T) {
	apply := applier(t)
	if err := apply(dep("dep_one", "gpu-01", 0, 8001), dep("dep_two", "gpu-01", 1, 8002)); err != nil {
		t.Fatal(err)
	}
	if err := apply(dep("dep_one", "gpu-01", 0, 8002), dep("dep_two", "gpu-01", 1, 8001)); err != nil {
		t.Errorf("a straight swap was refused: %v", err)
	}
}

// A deployment with no port yet — `defined`, nothing assigned — is not in
// contention with anything, and several of them are not in contention with
// each other.
func TestDeploymentsWithNoPortDoNotCollide(t *testing.T) {
	apply := applier(t)
	if err := apply(dep("dep_one", "gpu-01", 0, 0), dep("dep_two", "gpu-01", 1, 0)); err != nil {
		t.Errorf("two portless deployments collided: %v", err)
	}
}
