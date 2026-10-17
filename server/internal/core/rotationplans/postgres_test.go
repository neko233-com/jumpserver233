package rotationplans

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotationPlanPostgresTakeoverReconcilesReceiptAndIsolatesOrganizations(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("rotation-state-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	b, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	t.Cleanup(func() { _ = a.Delete("rotation-plans"); _ = b.Delete("rotation-plans"); _ = docs.Close() })
	_, f, _ := newFixture(t)
	path := filepath.Join(t.TempDir(), "plans.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	s.SetRunner(f.runner())
	p := saveManual(t, s, "account-a")
	run, e := s.Submit(context.Background(), testActor(), p.ID, "pg-rotation-takeover", false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("synthetic owned result write failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	assert.Equal(t, 1, f.calls)
	s.Close()
	raw, e := a.Load("rotation-plans")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Synthetic rotation metadata")
	assert.NotContains(t, string(raw), "synthetic-user-account")
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	result := drive(t, peer, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, 1, f.calls)
	other, e := Open(path, make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	_, _, e = other.Plans(0, 10)
	require.NoError(t, e)
	_, e = other.Plan(p.ID)
	assert.ErrorIs(t, e, ErrNotFound)
}
