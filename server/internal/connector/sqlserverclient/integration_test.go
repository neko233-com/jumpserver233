package sqlserverclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sqlserverfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func query(sql string, ro bool) Input {
	return Input{SQL: sql, ReadOnly: ro, RowLimit: 50, TimeoutSeconds: 10}
}
func TestRealSQLServerVerifiedTLSParametersMultipleResultsAndReadonly(t *testing.T) {
	target, secret := sqlserverfixture.Load(t)
	require.NoError(t, Ping(context.Background(), target, secret))
	bad := target
	bad.ServerName = "untrusted.invalid"
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.RootCAPEM = ""
	assert.Error(t, Ping(context.Background(), bad, secret))
	in := query("SELECT @p1 AS message, CAST(NULL AS nvarchar(10)) AS optional; SELECT DB_NAME() AS database_name", true)
	in.Parameters = []json.RawMessage{json.RawMessage(`"private-bound-值"`)}
	r, e := Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	require.Len(t, r.Rows, 1)
	assert.Equal(t, "private-bound-值", *r.Rows[0][0])
	assert.Nil(t, r.Rows[0][1])
	require.Len(t, r.ResultSets, 1)
	assert.Equal(t, "qa", *r.ResultSets[0].Rows[0][0])
	assert.Equal(t, "rolled_back", r.Transaction)
	for _, s := range []string{"SELECT 1 INTO dbo.must_not_exist", "SELECT 1; CREATE TABLE dbo.must_not_exist(id int)", "EXEC sp_executesql N'CREATE TABLE dbo.must_not_exist(id int)'", "SELECT NEXT VALUE FOR dbo.no_sequence", "SELECT 1COMMIT; SELECT 1DELETE FROM dbo.must_not_exist"} {
		r, e = Execute(context.Background(), target, secret, query(s, true), nil)
		assert.ErrorIs(t, e, sqlclient.ErrDenied)
		assert.Equal(t, "not_started", r.Transaction)
	}
	r, e = Execute(context.Background(), target, secret, query("SELECT OBJECT_ID('dbo.must_not_exist')", true), nil)
	require.NoError(t, e)
	assert.Nil(t, r.Rows[0][0])
}
func TestRealSQLServerWritesCountsProceduresAndUncertainPartialBatch(t *testing.T) {
	target, secret := sqlserverfixture.Load(t)
	table := "dbo.jq_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	proc := "dbo.jp_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	defer Execute(context.Background(), target, secret, query("DROP TABLE IF EXISTS "+table+"; DROP PROCEDURE IF EXISTS "+proc, false), nil)
	r, e := Execute(context.Background(), target, secret, query("CREATE TABLE "+table+"(id int NOT NULL PRIMARY KEY, value nvarchar(100))", false), nil)
	require.NoError(t, e)
	assert.Equal(t, "server_managed", r.Transaction)
	in := query("INSERT INTO "+table+"(id,value) VALUES (1,@p1),(2,@p1)", false)
	in.Parameters = []json.RawMessage{json.RawMessage(`"private-value"`)}
	r, e = Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	require.NotNil(t, r.AffectedRowsKnown)
	assert.True(t, *r.AffectedRowsKnown)
	assert.EqualValues(t, 2, r.AffectedRows)
	r, e = Execute(context.Background(), target, secret, query("INSERT INTO "+table+"(id) VALUES (3); INSERT INTO "+table+"(id) VALUES (3)", false), nil)
	require.Error(t, e)
	assert.Equal(t, "unknown", r.Transaction)
	assert.NotContains(t, e.Error(), table)
	r, e = Execute(context.Background(), target, secret, query("SELECT COUNT(*) FROM "+table, true), nil)
	require.NoError(t, e)
	assert.Equal(t, "3", *r.Rows[0][0])
	r, e = Execute(context.Background(), target, secret, query("CREATE PROCEDURE "+proc+" AS BEGIN SELECT N'first' AS one; SELECT N'second' AS two; END", false), nil)
	require.NoError(t, e)
	r, e = Execute(context.Background(), target, secret, query("EXEC "+proc, false), nil)
	require.NoError(t, e)
	assert.Equal(t, "first", *r.Rows[0][0])
	require.Len(t, r.ResultSets, 1)
	assert.Equal(t, "second", *r.ResultSets[0].Rows[0][0])
}
func TestRealSQLServerLimitsCancellationAuthorizationAndBinary(t *testing.T) {
	target, secret := sqlserverfixture.Load(t)
	in := query("SELECT 1 UNION ALL SELECT 2; SELECT 3", true)
	in.RowLimit = 1
	r, e := Execute(context.Background(), target, secret, in, nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.Equal(t, "result_limit", r.ErrorCode)
	r, e = Execute(context.Background(), target, secret, query("SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 3000000)", true), nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.True(t, r.Truncated)
	r, e = Execute(context.Background(), target, secret, query("SELECT CAST(0x00ff AS varbinary(2)), REPLICATE(CAST(N'x' AS nvarchar(max)), 9000)", true), nil)
	require.NoError(t, e)
	assert.Equal(t, "0x00ff", *r.Rows[0][0])
	assert.Len(t, *r.Rows[0][1], sqlclient.MaxCellBytes)
	assert.True(t, r.Truncated)
	r, e = Execute(context.Background(), target, secret, query("SELECT 'private-denied'", false), func() error { return errors.New("revoked") })
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "not_started", r.Transaction)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	r, e = Execute(ctx, target, secret, query("WAITFOR DELAY '00:00:05'; SELECT 1", false), nil)
	assert.Error(t, e)
	assert.Equal(t, "cancelled", r.ErrorCode)
	assert.Contains(t, []string{"unknown", "not_started"}, r.Transaction)
	r, e = Execute(context.Background(), target, secret, query("SELECT N'private-before-error'; THROW 50000,N'private-error',1", false), nil)
	assert.Error(t, e)
	assert.NotContains(t, fmt.Sprint(e), "private-")
	assert.Equal(t, "unknown", r.Transaction)
}
func TestRealSQLServerPinnedSSHGateway(t *testing.T) {
	target, secret := sqlserverfixture.Load(t)
	destination := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	loopback := postgresfixture.LoopbackForward(t, destination)
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{destination: loopback})
	require.NoError(t, e)
	defer g.Close()
	host, port, e := net.SplitHostPort(g.Address())
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	r, e := Execute(context.Background(), target, secret, query("SELECT DB_NAME()", true), nil)
	require.NoError(t, e)
	assert.Equal(t, "qa", *r.Rows[0][0])
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	assert.Error(t, Ping(context.Background(), target, secret))
}

func TestRealSQLServerClosingLimitedReadersDoesNotReuseTheirBuffers(t *testing.T) {
	target, secret := sqlserverfixture.Load(t)
	for i := 0; i < 10; i++ {
		_, e := Execute(context.Background(), target, secret, query("SELECT REPLICATE(CAST(N'x' AS nvarchar(max)),3000000)", true), nil)
		require.ErrorIs(t, e, sqlclient.ErrResultLimit)
		out, e := Execute(context.Background(), target, secret, query("SELECT 233", true), nil)
		require.NoError(t, e)
		require.Len(t, out.Rows, 1)
		assert.Equal(t, "233", *out.Rows[0][0])
	}
}
