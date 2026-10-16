package postgresclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealPostgresTLSParametersTransactionsBoundsAndRevocation(t *testing.T) {
	target, secret := postgresfixture.Load(t)
	ctx := context.Background()
	require.NoError(t, postgresclient.Ping(ctx, target, secret))
	early, stop := context.WithCancel(ctx)
	stop()
	cancelled, e := postgresclient.Execute(early, target, secret, postgresclient.Input{SQL: "SELECT 1", RowLimit: 1, TimeoutSeconds: 5}, nil)
	assert.ErrorIs(t, e, context.Canceled)
	assert.Equal(t, "cancelled", cancelled.ErrorCode)
	bad := target
	bad.ServerName = "wrong.invalid"
	require.ErrorIs(t, postgresclient.Ping(ctx, bad, secret), postgresclient.ErrUnavailable)
	bad = target
	bad.RootCAPEM = ""
	require.ErrorIs(t, postgresclient.Ping(ctx, bad, secret), postgresclient.ErrUnavailable)
	run := func(sql string, readonly bool, params ...json.RawMessage) (postgresclient.Result, error) {
		return postgresclient.Execute(ctx, target, secret, postgresclient.Input{SQL: sql, Parameters: params, RowLimit: 10, ReadOnly: readonly, TimeoutSeconds: 5}, nil)
	}
	table := fmt.Sprintf("qa_query_%d", time.Now().UnixNano())
	_, e = run("CREATE TABLE "+table+" (id int, value text)", false)
	require.NoError(t, e)
	t.Cleanup(func() { _, _ = run("DROP TABLE IF EXISTS "+table, false) })
	marker := `private-parameter '); DROP TABLE ` + table + `; --`
	p, _ := json.Marshal(marker)
	r, e := run("SELECT $1::text, NULL::text, $2::int", true, p, json.RawMessage("42"))
	require.NoError(t, e)
	require.Len(t, r.Rows, 1)
	assert.Equal(t, marker, *r.Rows[0][0])
	assert.Nil(t, r.Rows[0][1])
	assert.Equal(t, "42", *r.Rows[0][2])
	assert.Equal(t, "rolled_back", r.Transaction)
	_, e = run("INSERT INTO "+table+" VALUES (1,'forbidden')", true)
	require.Error(t, e)
	_, e = run("SELECT set_config('transaction_read_only','off',true)", true)
	require.Error(t, e)
	r, e = run("INSERT INTO "+table+" VALUES (1,'kept')", false)
	require.NoError(t, e)
	assert.Equal(t, "committed", r.Transaction)
	r, e = postgresclient.Execute(ctx, target, secret, postgresclient.Input{SQL: "INSERT INTO " + table + " SELECT n,'overflow' FROM generate_series(2,20) n RETURNING id", RowLimit: 2, TimeoutSeconds: 5}, nil)
	assert.ErrorIs(t, e, postgresclient.ErrResultLimit)
	assert.True(t, r.Truncated)
	assert.Equal(t, "rolled_back", r.Transaction)
	_, e = run("SELECT 1; DELETE FROM "+table, false)
	require.Error(t, e)
	r, e = postgresclient.Execute(ctx, target, secret, postgresclient.Input{SQL: "INSERT INTO " + table + " VALUES(99,'revoked')", RowLimit: 1, TimeoutSeconds: 5}, func() error { return postgresclient.ErrDenied })
	assert.ErrorIs(t, e, postgresclient.ErrDenied)
	assert.Equal(t, "rolled_back", r.Transaction)
	r, e = run("SELECT count(*) FROM "+table, true)
	require.NoError(t, e)
	assert.Equal(t, "1", *r.Rows[0][0])
	r, e = run("SELECT repeat('界',10000)", true)
	require.NoError(t, e)
	assert.True(t, r.Truncated)
	assert.LessOrEqual(t, len(*r.Rows[0][0]), postgresclient.MaxCellBytes)
	cancelCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, e = postgresclient.Execute(cancelCtx, target, secret, postgresclient.Input{SQL: "SELECT pg_sleep(5)", RowLimit: 1, TimeoutSeconds: 5}, nil)
	require.Error(t, e)
	assert.Less(t, time.Since(started), 3*time.Second)
	_, e = run("SELECT $1::int", true, json.RawMessage(`"private-invalid-int"`))
	require.Error(t, e)
	assert.NotContains(t, e.Error(), "private-invalid-int")
}
func TestRealPostgresThroughPinnedGatewayAndDeadlineCleanup(t *testing.T) {
	target, secret := postgresfixture.Load(t)
	destination := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	gateway, e := sshgateway.Start("127.0.0.1:0", map[string]string{"postgres.synthetic.invalid:5432": destination})
	require.NoError(t, e)
	defer gateway.Close()
	host, port, _ := net.SplitHostPort(gateway.Address())
	n, _ := strconv.Atoi(port)
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: gateway.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	target.Host = "postgres.synthetic.invalid"
	target.Port = 5432
	r, e := postgresclient.Execute(context.Background(), target, secret, postgresclient.Input{SQL: "SELECT current_database()", RowLimit: 1, TimeoutSeconds: 5, ReadOnly: true}, nil)
	require.NoError(t, e)
	assert.Equal(t, "qa", *r.Rows[0][0])
	assert.Greater(t, gateway.Forwards(), int64(0))
	require.Eventually(t, func() bool { return gateway.Active() == 0 }, 3*time.Second, 10*time.Millisecond)
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	require.Error(t, postgresclient.Ping(context.Background(), target, secret))
}
