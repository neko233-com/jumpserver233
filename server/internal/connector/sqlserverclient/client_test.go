package sqlserverclient

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSQLServerExplicitConfigurationAndParameters(t *testing.T) {
	t.Setenv("SQLSERVER_DSN", "must-not-be-read")
	p, e := config(Target{Host: "db.invalid", Port: 1433, Username: "qa", Settings: sqlclient.Settings{Database: "qa", TLSMode: "verify-full"}}, Credentials{Password: "secret"})
	require.NoError(t, e)
	assert.EqualValues(t, msdsn.EncryptionRequired, p.Encryption)
	assert.False(t, p.TrustServerCertificate)
	assert.False(t, p.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS12), p.TLSConfig.MinVersion)
	assert.True(t, p.DisableRetry)
	a, e := bind([]json.RawMessage{json.RawMessage(`"private"`), json.RawMessage(`null`), json.RawMessage(`9007199254740993`)})
	require.NoError(t, e)
	assert.Equal(t, sql.Named("p1", "private"), a[0])
	assert.Equal(t, sql.Named("p2", nil), a[1])
	assert.Equal(t, sql.Named("p3", "9007199254740993"), a[2])
	assert.Equal(t, "0x00ff", cell([]byte{0, 255}, "VARBINARY"))
}
func TestSQLServerReadonlyDeniedBeforeOpeningAnyConnection(t *testing.T) {
	r, e := Execute(context.Background(), Target{Settings: sqlclient.Settings{ReadOnly: true}}, Credentials{}, Input{SQL: "SELECT 1 INTO dbo.denied", RowLimit: 1, TimeoutSeconds: 1}, nil)
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "read_only", r.ErrorCode)
	assert.Equal(t, "not_started", r.Transaction)
}
