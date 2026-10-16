package cluster

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestTryAcquireSerializesNodesAndReleasesForFailover(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the PostgreSQL leader-election integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clusterID := "test-jms233-" + time.Now().UTC().Format("20060102150405.000000000")

	active, acquired, err := TryAcquire(ctx, databaseURL, clusterID)
	if err != nil || !acquired {
		t.Fatalf("first TryAcquire() = (%v, %v), want acquired", acquired, err)
	}
	defer func() { _ = active.Close(context.Background()) }()

	standby, acquired, err := TryAcquire(ctx, databaseURL, clusterID)
	if err != nil || acquired || standby != nil {
		t.Fatalf("second TryAcquire() = (%v, %v, %v), want not acquired", standby, acquired, err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := active.Close(closeCtx); err != nil {
		closeCancel()
		t.Fatalf("release active lease: %v", err)
	}
	closeCancel()

	standby, acquired, err = TryAcquire(ctx, databaseURL, clusterID)
	if err != nil || !acquired || standby == nil {
		t.Fatalf("standby TryAcquire() after release = (%v, %v), want acquired", acquired, err)
	}
	if err := standby.Check(ctx); err != nil {
		t.Fatalf("standby Check() = %v", err)
	}
	if err := standby.Close(ctx); err != nil {
		t.Fatalf("release standby lease: %v", err)
	}
}

func TestTryAcquireRejectsInvalidClusterID(t *testing.T) {
	if _, acquired, err := TryAcquire(context.Background(), "", " "); err != ErrInvalidClusterID || acquired {
		t.Fatalf("TryAcquire() = (acquired=%v, err=%v), want invalid cluster ID", acquired, err)
	}
}

func TestTryAcquireRejectsInvalidDatabaseURL(t *testing.T) {
	_, acquired, err := TryAcquire(context.Background(), "not a postgres connection string", "cluster-a")
	if acquired || err != ErrInvalidDatabaseConfig {
		t.Fatalf("TryAcquire() = (acquired=%v, err=%v), want invalid database configuration", acquired, err)
	}
}
