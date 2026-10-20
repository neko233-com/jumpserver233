package smsmfa

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMSMFAPostgresReopenPreservesCodeHashProofAndSettingReceipt(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL fixture")
	}
	docs, e := storage.OpenPostgres(t.Context(), dsn, fmt.Sprintf("sms-mfa-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	for _, name := range []string{"users", "auth-sessions", "sms-mfa"} {
		defer docs.Delete(name)
	}
	root := t.TempDir()
	a, e := auth.OpenServiceWithDocumentsAndVaultKey(filepath.Join(root, "users.json"), docs, make([]byte, 32))
	require.NoError(t, e)
	u, e := a.Bootstrap("sms.admin", "synthetic-sms-admin-password")
	require.NoError(t, e)
	f := &fakeTransport{}
	f.revision.Store(1)
	s, e := Open(filepath.Join(root, "sms.json"), make([]byte, 32), docs, a, f)
	require.NoError(t, e)
	in := Input{Config: Config{Enabled: true, Policy: "all"}, RequestID: "sms-postgres-001"}
	first, e := s.Save(in, u.ID)
	require.NoError(t, e)
	ticket, _ := begin(t, s, a, u)
	_, e = s.BindLoginPhone(t.Context(), ticket, "192.0.2.1", "+8613800000000", "sms-pg-bind-001")
	require.NoError(t, e)
	code := f.last()
	s.Close()
	reopenedAuth, e := auth.OpenServiceWithDocumentsAndVaultKey(filepath.Join(root, "other-users.json"), docs, make([]byte, 32))
	require.NoError(t, e)
	again, e := Open(filepath.Join(root, "other-sms.json"), make([]byte, 32), docs, reopenedAuth, f)
	require.NoError(t, e)
	defer again.Close()
	receipt, e := again.Save(in, u.ID)
	require.NoError(t, e)
	assert.Equal(t, first, receipt)
	var session auth.LoginSession
	require.NoError(t, again.Finish(t.Context(), ticket, "192.0.2.1", code, func(v Verified, stamp func() string) error {
		var e error
		session, e = reopenedAuth.ResumeLoginProofWithSMSContact(v.Proof, v.Phone, v.Generation)
		if e != nil {
			return e
		}
		return reopenedAuth.SetSessionSMSStamp(session.AccessToken, v.UserID, stamp())
	}))
	assert.True(t, session.User.SMSMFAEnabled)
	assert.True(t, again.ValidStamp(u.ID, reopenedAuth.SessionSMSStamp(session.AccessToken)))
	raw, e := docs.Load("sms-mfa")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "+8613800000000")
}
