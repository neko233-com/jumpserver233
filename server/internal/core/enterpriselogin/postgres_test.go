package enterpriselogin

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnterpriseLoginPostgresReloadPreservesEncryptedConfigurationAndReceipts(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for enterprise login PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, fmt.Sprintf("enterprise-login-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	scoped, e := docs.Scoped(source)
	require.NoError(t, e)
	for _, kind := range []string{"wecom", "dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			defer scoped.Delete(kind + "-config")
			path := filepath.Join(t.TempDir(), kind+".json")
			s, e := Open(kind, path, make([]byte, 32), scoped, "http://127.0.0.1:5177", identityscope.Prefix(source), &fakeProvider{})
			require.NoError(t, e)
			in := input(kind)
			first, e := s.Save(in, "actor", "admin")
			require.NoError(t, e)
			s.Close()
			again, e := Open(kind, path, make([]byte, 32), scoped, "http://127.0.0.1:5177", identityscope.Prefix(source), &fakeProvider{})
			require.NoError(t, e)
			defer again.Close()
			replayed, e := again.Save(in, "actor", "admin")
			require.NoError(t, e)
			assert.Equal(t, first, replayed)
			assert.True(t, again.Snapshot().HasClientSecret)
		})
	}
}
