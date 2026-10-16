package sqlclient

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSQLServerAuditNestedCommentsUnicodeAndDelimitedIdentifiers(t *testing.T) {
	a, e := AuditSQLServer("/* outer /* secret */ hidden */ SELECT N'private''值', [private]]name], \"private\", 0xABC -- private\n, @p1")
	require.NoError(t, e)
	assert.NotContains(t, a, "private")
	assert.NotContains(t, a, "secret")
	assert.NotContains(t, a, "hidden")
	assert.True(t, ReadOnlySQLServer(a))
	for _, sql := range []string{"SELECT 'bad", "SELECT [bad", "/* bad", "SELECT \x00"} {
		_, e = AuditSQLServer(sql)
		assert.ErrorIs(t, e, ErrInvalid)
	}
}
func TestSQLServerReadonlyRejectsMutationAcrossAnEntireBatch(t *testing.T) {
	for _, sql := range []string{"SELECT 1 INTO dbo.test", "SELECT 1; DELETE FROM dbo.test", "WITH x AS (SELECT 1 AS n) UPDATE dbo.test SET id=1", "SELECT NEXT VALUE FOR dbo.seq", "SELECT * FROM OPENROWSET('secret')", "EXEC dbo.proc", "SELECT 1 COMMIT", "SELECT 1; SET QUOTED_IDENTIFIER OFF", "SELECT 1COMMIT; SELECT 1DELETE FROM dbo.test", "SELECT 1e0EXEC dbo.proc", "SELECT ١COMMIT", "SELECT 1; SETUSER N'dbo'"} {
		a, e := AuditSQLServer(sql)
		require.NoError(t, e)
		assert.False(t, ReadOnlySQLServer(a), sql)
	}
	a, e := AuditSQLServer("SELECT @p1, item233, 123.45, 1e-3, 0xDEADBEEF")
	require.NoError(t, e)
	assert.Equal(t, "SELECT @p1, item233, ?, ?, ?", a)
	for _, sql := range []string{"SELECT @p1, N'COMMIT', [DROP] FROM [secret]", "WITH x AS (SELECT 1 AS n) SELECT * FROM x", "SELECT 1; SELECT 2"} {
		a, e := AuditSQLServer(sql)
		require.NoError(t, e)
		assert.True(t, ReadOnlySQLServer(a), sql)
	}
}
func TestCloneResultCopiesAdditionalTables(t *testing.T) {
	value := "private-row"
	r := Result{ResultSets: []ResultSet{{Columns: []Column{{Name: "extra"}}, Rows: [][]*string{{&value}}}}}
	copy := CloneResult(r)
	*copy.ResultSets[0].Rows[0][0] = "mutated"
	copy.ResultSets[0].Columns[0].Name = "changed"
	assert.Equal(t, "private-row", *r.ResultSets[0].Rows[0][0])
	assert.Equal(t, "extra", r.ResultSets[0].Columns[0].Name)
}
