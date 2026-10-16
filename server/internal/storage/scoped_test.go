package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopedDocumentsValidateKeys(t *testing.T) {
	root := &Documents{}
	for _, scope := range []string{"", "../escape", "UPPER", "org:escape", "with space"} {
		_, e := root.Scoped(scope)
		assert.ErrorIs(t, e, ErrInvalidDocument)
	}
	child, e := root.Scoped("00000000-0000-0000-0000-000000000002")
	require.NoError(t, e)
	key, e := child.documentKey("assets")
	require.NoError(t, e)
	assert.Equal(t, "00000000-0000-0000-0000-000000000002:assets", key)
	_, e = child.Scoped("nested")
	assert.ErrorIs(t, e, ErrInvalidDocument)
	require.NoError(t, child.Close())
}
func TestScopedDocumentsIsolateImportSaveDeleteAndClose(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for scoped PostgreSQL documents")
	}
	namespace := fmt.Sprintf("organization-docs-%d", time.Now().UnixNano())
	root, e := OpenPostgres(context.Background(), url, namespace)
	require.NoError(t, e)
	t.Cleanup(func() {
		_, _ = root.db.Exec(`DELETE FROM jms233_state_documents WHERE namespace=$1`, namespace)
		_ = root.Close()
	})
	a, e := root.Scoped("organization-a")
	require.NoError(t, e)
	b, e := root.Scoped("organization-b")
	require.NoError(t, e)
	require.NoError(t, root.Save("assets", []byte(`{"scope":"root"}`)))
	require.NoError(t, a.Save("assets", []byte(`{"scope":"a"}`)))
	path := filepath.Join(t.TempDir(), "assets.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"scope":"b"}`), 0600))
	raw, e := b.LoadOrImport("assets", path)
	require.NoError(t, e)
	assert.JSONEq(t, `{"scope":"b"}`, string(raw))
	raw, e = a.Load("assets")
	require.NoError(t, e)
	assert.JSONEq(t, `{"scope":"a"}`, string(raw))
	require.NoError(t, a.Delete("assets"))
	_, e = a.Load("assets")
	assert.ErrorIs(t, e, ErrDocumentNotFound)
	raw, e = root.Load("assets")
	require.NoError(t, e)
	assert.JSONEq(t, `{"scope":"root"}`, string(raw))
	require.NoError(t, a.Close())
	require.NoError(t, root.Ping())
	raw, e = b.Load("assets")
	require.NoError(t, e)
	assert.JSONEq(t, `{"scope":"b"}`, string(raw))
}
