package rotationplans

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCheckPostgresTakeoverDoesNotRepeatAuthentication(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("account-check-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	b, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	t.Cleanup(func() { _ = a.Delete("rotation-plans"); _ = b.Delete("rotation-plans"); _ = docs.Close() })
	_, f, _, calls, _ := checkFixture(t)
	r := f.runner()
	r.AuthorizeCheck = func(Actor) error { return nil }
	r.Check = func(context.Context, Intent, func() error) (Outcome, error) {
		calls.Add(1)
		return Outcome{State: "succeeded", CheckDurationMS: 1}, nil
	}
	path := filepath.Join(t.TempDir(), "plans.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	s.SetRunner(r)
	p := saveManual(t, s, "account-a")
	submitted, e := s.Check(context.Background(), testActor(), p.ID, "check-pg-result", false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("owned check result write failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	assert.EqualValues(t, 1, calls.Load())
	s.Close()
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(r)
	again, e := peer.Check(context.Background(), testActor(), p.ID, submitted.RequestID, false)
	require.NoError(t, e)
	assert.Equal(t, submitted.ID, again.ID)
	assert.Equal(t, "interrupted", again.Items[0].State)
	peer.Tick()
	waitIdle(t, peer)
	assert.EqualValues(t, 1, calls.Load())
	other, e := Open(path, make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	other.SetRunner(r)
	_, e = other.Check(context.Background(), testActor(), p.ID, submitted.RequestID, false)
	assert.ErrorIs(t, e, ErrNotFound)
}
