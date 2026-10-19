package credentialpolicy

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSSHPasswordPolicyScopedPostgresFailover(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PostgreSQL fixture not configured")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("ssh-policy-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("org-a")
	require.NoError(t, e)
	b, e := docs.Scoped("org-b")
	require.NoError(t, e)
	key := make([]byte, 32)
	source, e := Open(filepath.Join(t.TempDir(), "a.json"), key, a)
	require.NoError(t, e)
	p := source.Snapshot()
	p.MinLength = 64
	in := Input{RequestID: "takeover-policy", Policy: p}
	saved, e := source.Save(in, "admin", "Admin")
	require.NoError(t, e)
	next, e := Open(filepath.Join(t.TempDir(), "next.json"), key, a)
	require.NoError(t, e)
	assert.Equal(t, saved, next.Snapshot())
	_, e = next.Save(in, "admin", "Admin")
	require.NoError(t, e)
	assert.Len(t, next.Audit(), 1)
	isolated, e := Open(filepath.Join(t.TempDir(), "b.json"), key, b)
	require.NoError(t, e)
	assert.Equal(t, Defaults(), isolated.Snapshot().Rules)
}
