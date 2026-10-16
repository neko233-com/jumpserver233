package clickhouseclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/clickhousefixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRealClickHouseVerifiedTLSBoundTypesAndReadonly(t *testing.T) {
	target, secret := clickhousefixture.Load(t)
	require.NoError(t, Ping(context.Background(), target, secret))
	bad := target
	bad.ServerName = "untrusted.invalid"
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.RootCAPEM = ""
	assert.Error(t, Ping(context.Background(), bad, secret))
	in := query("SELECT {p1:String} AS message, {p2:Nullable(UInt64)} AS optional, {p3:UInt64} AS precise, {p4:Array(Nullable(String))} AS items, {p5:Tuple(String,UInt64)} AS pair, {p6:Map(String,UInt64)} AS mapping", true)
	in.Parameters = []json.RawMessage{json.RawMessage(`"private-bound-中\t\\N'"`), json.RawMessage(`null`), json.RawMessage(`18446744073709551615`), json.RawMessage(`["a'b",null,"x\ty"]`), json.RawMessage(`["值",233]`), json.RawMessage(`{"a":1,"z":2}`)}
	out, e := Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	require.Len(t, out.Rows, 1)
	assert.Equal(t, "private-bound-中\t\\N'", *out.Rows[0][0])
	assert.Nil(t, out.Rows[0][1])
	assert.Equal(t, "18446744073709551615", *out.Rows[0][2])
	assert.Contains(t, *out.Rows[0][3], "a'b")
	assert.Contains(t, *out.Rows[0][3], "null")
	assert.Contains(t, *out.Rows[0][4], "值")
	assert.Contains(t, *out.Rows[0][5], "\"a\":1")
	assert.Equal(t, "read_only", out.Transaction)
	for _, sql := range []string{"CREATE TABLE qa.never_created(id UInt8) ENGINE=Memory", "INSERT INTO qa.never_created VALUES(1)", "SELECT 1; DROP TABLE qa.never_created"} {
		out, e = Execute(context.Background(), target, secret, query(sql, true), nil)
		assert.Error(t, e)
		assert.NotEqual(t, "committed", out.Transaction)
	}
	for _, sql := range []string{"SELECT 1 SETTINGS readonly=0", "SELECT 1 FORMAT CSV", "SELECT 1 INTO OUTFILE '/tmp/private'"} {
		_, e = Execute(context.Background(), target, secret, query(sql, true), nil)
		assert.ErrorIs(t, e, sqlclient.ErrInvalid)
	}
}
func TestRealClickHouseWritesCountsAndNoClaimedRollback(t *testing.T) {
	target, secret := clickhousefixture.Load(t)
	table := "qa.jq_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	defer Execute(context.Background(), target, secret, query("DROP TABLE IF EXISTS "+table, false), nil)
	out, e := Execute(context.Background(), target, secret, query("CREATE TABLE "+table+"(id UInt64, value String) ENGINE=Memory", false), nil)
	require.NoError(t, e)
	assert.Equal(t, "server_managed", out.Transaction)
	in := query("INSERT INTO "+table+" SELECT number, {p1:String} FROM numbers(2)", false)
	in.Parameters = []json.RawMessage{json.RawMessage(`"private-written"`)}
	out, e = Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	assert.Equal(t, "server_managed", out.Transaction)
	if out.AffectedRowsKnown != nil && *out.AffectedRowsKnown {
		assert.EqualValues(t, 2, out.AffectedRows)
	}
	out, e = Execute(context.Background(), target, secret, query("SELECT count() FROM "+table, true), nil)
	require.NoError(t, e)
	assert.Equal(t, "2", *out.Rows[0][0])
	out, e = Execute(context.Background(), target, secret, query("INSERT INTO "+table+" SELECT throwIf(number=2), 'private' FROM numbers(3)", false), nil)
	require.Error(t, e)
	assert.Equal(t, "unknown", out.Transaction)
	assert.NotContains(t, e.Error(), "private")
	assert.NotEmpty(t, out.DatabaseCode)
}
func TestRealClickHouseLimitsBinaryCancellationAndRevocation(t *testing.T) {
	target, secret := clickhousefixture.Load(t)
	in := query("SELECT number FROM numbers(3)", true)
	in.RowLimit = 1
	out, e := Execute(context.Background(), target, secret, in, nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.True(t, out.Truncated)
	out, e = Execute(context.Background(), target, secret, query("SELECT unhex('00ff'), unhex('ff'), repeat('x',9000)", true), nil)
	require.NoError(t, e)
	assert.Equal(t, "0x00ff", *out.Rows[0][0])
	assert.Equal(t, "0xff", *out.Rows[0][1])
	assert.Len(t, *out.Rows[0][2], sqlclient.MaxCellBytes)
	assert.True(t, out.Truncated)
	_, e = Execute(context.Background(), target, secret, query("SELECT repeat('xxxxxxxx',700000)", true), nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	out, e = Execute(context.Background(), target, secret, query("SELECT 'private-denied'", false), func() error { return errors.New("denied") })
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "not_started", out.Transaction)
	marker := "jms233_cancel_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := Execute(ctx, target, secret, query("SELECT sleepEachRow(0.1) FROM numbers(20) /*"+marker+"*/", true), nil)
		done <- e
	}()
	require.Eventually(t, func() bool {
		r, e := Execute(context.Background(), target, secret, query("SELECT count() FROM system.processes WHERE position(query, '"+marker+"') > 0 AND NOT startsWith(query, 'SELECT count()')", true), nil)
		return e == nil && len(r.Rows) > 0 && *r.Rows[0][0] == "1"
	}, 5*time.Second, 50*time.Millisecond)
	cancel()
	assert.ErrorIs(t, <-done, context.Canceled)
	require.Eventually(t, func() bool {
		r, e := Execute(context.Background(), target, secret, query("SELECT count() FROM system.processes WHERE position(query, '"+marker+"') > 0 AND NOT startsWith(query, 'SELECT count()')", true), nil)
		return e == nil && len(r.Rows) > 0 && *r.Rows[0][0] == "0"
	}, 4*time.Second, 50*time.Millisecond)
}
func TestRealClickHousePinnedSSHGateway(t *testing.T) {
	target, secret := clickhousefixture.Load(t)
	destination := net.JoinHostPort("clickhouse.synthetic.invalid", strconv.Itoa(target.Port))
	loopback := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{destination: loopback})
	require.NoError(t, e)
	defer g.Close()
	host, port, e := net.SplitHostPort(g.Address())
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	target.Host = "clickhouse.synthetic.invalid"
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	out, e := Execute(context.Background(), target, secret, query("SELECT currentDatabase()", true), nil)
	require.NoError(t, e)
	assert.Equal(t, "qa", *out.Rows[0][0])
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	assert.Error(t, Ping(context.Background(), target, secret))
}
