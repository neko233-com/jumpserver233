package mysqlclient

import (
	"context"
	"encoding/json"
	"errors"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strings"
	"testing"
)

func TestTextFallbackOnlyAfterUnsupportedPreparationWithoutParameters(t *testing.T) {
	assert.True(t, textFallback(&mysql.MySQLError{Number: 1295}, 0))
	assert.False(t, textFallback(&mysql.MySQLError{Number: 1295}, 1))
	assert.False(t, textFallback(&mysql.MySQLError{Number: 1064}, 0))
	assert.False(t, textFallback(errors.New("not a server preparation error"), 0))
}

func TestMySQLConfigNeverInterpolatesOrReadsClientFilesAndRequiresVerifiedTLS(t *testing.T) {
	target := Target{Host: "127.0.0.1", Port: 3306, Username: "ops", Settings: sqlclient.Settings{Database: "qa", TLSMode: "verify-full"}}
	c, e := config(target, Credentials{Password: "vault-only"}, &wireBudget{})
	require.NoError(t, e)
	assert.Equal(t, "vault-only", c.Passwd)
	assert.False(t, c.MultiStatements)
	assert.False(t, c.InterpolateParams)
	assert.False(t, c.AllowAllFiles)
	assert.False(t, c.AllowCleartextPasswords)
	assert.False(t, c.AllowFallbackToPlaintext)
	require.NotNil(t, c.TLS)
	assert.False(t, c.TLS.InsecureSkipVerify)
	assert.Equal(t, "127.0.0.1", c.TLS.ServerName)
	assert.Empty(t, c.ServerPubKey)
	target.TLSMode = "skip-verify"
	_, e = config(target, Credentials{Password: "vault-only"}, &wireBudget{})
	assert.ErrorIs(t, e, sqlclient.ErrInvalid)
	for _, sql := range []string{"CALL writes()", "DROP TABLE x", "ALTER TABLE x ADD a int", "DO writes()"} {
		assert.False(t, readOnlyStatement(sql))
	}
	assert.True(t, readOnlyStatement("SELECT ?"))
	args, e := bind([]json.RawMessage{json.RawMessage("null"), json.RawMessage("12345678901234567890"), json.RawMessage(`{"x":1}`)})
	require.NoError(t, e)
	assert.Nil(t, args[0])
	assert.Equal(t, "12345678901234567890", args[1])
	assert.Equal(t, `{"x":1}`, args[2])
}
func TestMySQLWireBudgetClosesConnectionBeforeUnboundedRead(t *testing.T) {
	reader, writer := net.Pipe()
	defer writer.Close()
	budget := &wireBudget{}
	budget.remaining.Store(4)
	c := &budgetConnection{Conn: reader, budget: budget}
	defer c.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = writer.Write([]byte(strings.Repeat("a", 32))) }()
	buffer := make([]byte, 16)
	n, e := c.Read(buffer)
	require.NoError(t, e)
	assert.Equal(t, 4, n)
	_, e = c.Read(buffer)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.True(t, budget.exceeded.Load())
	<-done
}
func TestMySQLEarlyCancellationNeverReportsCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e := Execute(ctx, Target{Host: "127.0.0.1", Port: 1, Username: "qa", Settings: sqlclient.Settings{Database: "qa", TLSMode: "disable"}}, Credentials{Password: "synthetic"}, Input{SQL: "SELECT 1", ReadOnly: true, RowLimit: 1, TimeoutSeconds: 1}, nil)
	require.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, "not_started", r.Transaction)
}
