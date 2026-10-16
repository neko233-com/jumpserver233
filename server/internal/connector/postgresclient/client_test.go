package postgresclient

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestValidationAndAuditNeverRetainLiteralOrCommentContents(t *testing.T) {
	for _, sql := range []string{"SELECT 'private-marker' /* private-marker */", `SELECT "private-marker", $tag$private-marker$tag$, 1234`, "SELECT E'private-marker\\\\'", `SELECT '\', $1 -- private-marker`} {
		redacted, e := AuditSQL(sql)
		require.NoError(t, e, sql)
		assert.NotContains(t, redacted, "private-marker")
		assert.NotContains(t, redacted, "1234")
	}
	for _, sql := range []string{"/* open", "SELECT 'open", "SELECT $body$open", "-- only comment", "COMMIT", "/* a */ BEGIN", "COPY t TO STDOUT", "SET transaction_read_only=off"} {
		_, e := AuditSQL(sql)
		assert.ErrorIs(t, e, ErrInvalid, sql)
	}
	in := Input{SQL: "SELECT $1::text", Parameters: []json.RawMessage{json.RawMessage(`"value"`)}, RowLimit: 1, TimeoutSeconds: 1}
	require.NoError(t, ValidateInput(in))
	values, e := parameters([]json.RawMessage{json.RawMessage(` null `), json.RawMessage(`"x"`), json.RawMessage(`{"a":1}`)})
	require.NoError(t, e)
	assert.Nil(t, values[0])
	assert.Equal(t, "x", string(values[1]))
	assert.Equal(t, `{"a":1}`, string(values[2]))
	in.Parameters = []json.RawMessage{json.RawMessage(`"\u0000"`)}
	assert.ErrorIs(t, ValidateInput(in), ErrInvalid)
	in.Parameters = nil
	in.RowLimit = MaxRows + 1
	assert.ErrorIs(t, ValidateInput(in), ErrInvalid)
}
func TestConnectionConfigurationIgnoresAmbientPostgresSettings(t *testing.T) {
	for key, value := range map[string]string{"PGHOST": "evil.invalid", "PGPASSWORD": "ambient-secret", "PGDATABASE": "evil", "PGSERVICE": "not-a-service", "PGSERVICEFILE": "missing-file", "PGPASSFILE": "missing-file", "PGSSLCERT": "missing-cert", "PGSSLKEY": "missing-key", "PGSSLROOTCERT": "missing-root", "PGOPTIONS": "-c role=evil", "PGCHANNELBINDING": "require"} {
		t.Setenv(key, value)
	}
	target := Target{Host: "127.0.0.1", Port: 5432, Username: "ops", Settings: Settings{Database: "qa", TLSMode: "verify-full"}}
	c, e := connectionConfig(target, Credentials{Password: "vault-secret"})
	require.NoError(t, e)
	assert.Equal(t, "vault-secret", c.Password)
	assert.Equal(t, "qa", c.Database)
	assert.Equal(t, "127.0.0.1", c.Host)
	assert.Equal(t, "prefer", c.ChannelBinding)
	assert.Empty(t, c.Fallbacks)
	assert.NotContains(t, c.RuntimeParams, "options")
	assert.NotContains(t, c.RuntimeParams, "role")
	require.NotNil(t, c.TLSConfig)
	assert.False(t, c.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, "127.0.0.1", c.TLSConfig.ServerName)
	target.TLSMode = "require"
	_, e = connectionConfig(target, Credentials{Password: "secret"})
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = parameters([]json.RawMessage{json.RawMessage(`"` + strings.Repeat("a", 65536) + `"`)})
	assert.ErrorIs(t, e, ErrInvalid)
}
