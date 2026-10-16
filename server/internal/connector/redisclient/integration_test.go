package redisclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/nosqlfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func command(args ...any) string { raw, _ := json.Marshal(args); return string(raw) }
func TestRealRedisTLSBinaryNullPrecisionAndReadonly(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "redis")
	require.NoError(t, Ping(context.Background(), target, secret))
	bad := target
	bad.ServerName = "untrusted.invalid"
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.RootCAPEM = ""
	assert.Error(t, Ping(context.Background(), bad, secret))
	key := "jms233_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	defer Execute(context.Background(), target, secret, query(command("DEL", key), false), nil)
	out, e := Execute(context.Background(), target, secret, query(command("SET", key, map[string]string{"base64": "AP8="}), false), nil)
	require.NoError(t, e)
	assert.Equal(t, "server_managed", out.Transaction)
	out, e = Execute(context.Background(), target, secret, query(command("GET", key), true), nil)
	require.NoError(t, e)
	assert.Equal(t, "binary", *out.Rows[0][1])
	assert.Equal(t, "0x00ff", *out.Rows[0][2])
	out, e = Execute(context.Background(), target, secret, query(command("GET", key+"missing"), true), nil)
	require.NoError(t, e)
	assert.Nil(t, out.Rows[0][2])
	assert.Equal(t, "read_only", out.Transaction)
	_, e = Execute(context.Background(), target, secret, query(command("SET", key, "9223372036854775806"), false), nil)
	require.NoError(t, e)
	out, e = Execute(context.Background(), target, secret, query(command("INCR", key), false), nil)
	require.NoError(t, e)
	assert.Equal(t, "9223372036854775807", *out.Rows[0][2])
	target.ReadOnly = true
	out, e = Execute(context.Background(), target, secret, query(command("SET", key, "denied"), false), nil)
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "not_started", out.Transaction)
}
func TestRealRedisLimitsCancellationAndRevocation(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "redis")
	key := "jms233_limit_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	defer Execute(context.Background(), target, secret, query(command("DEL", key), false), nil)
	_, e := Execute(context.Background(), target, secret, query(command("EVAL", "return redis.call('SET',KEYS[1],string.rep('x',5000000))", "1", key), false), nil)
	require.NoError(t, e)
	out, e := Execute(context.Background(), target, secret, query(command("GET", key), true), nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.True(t, out.Truncated)
	_, e = Execute(context.Background(), target, secret, query(command("SET", key, strings.Repeat("中", 4000)), false), nil)
	require.NoError(t, e)
	out, e = Execute(context.Background(), target, secret, query(command("GET", key), true), nil)
	require.NoError(t, e)
	assert.True(t, out.Truncated)
	assert.LessOrEqual(t, len(*out.Rows[0][2]), sqlclient.MaxCellBytes)
	_, e = Execute(context.Background(), target, secret, query(command("DEL", key), false), nil)
	require.NoError(t, e)
	_, e = Execute(context.Background(), target, secret, query(command("RPUSH", key, "a", "b", "c"), false), nil)
	require.NoError(t, e)
	in := query(command("LRANGE", key, "0", "-1"), true)
	in.RowLimit = 1
	_, e = Execute(context.Background(), target, secret, in, nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	out, e = Execute(ctx, target, secret, query(command("BLPOP", key+"empty", "0"), false), nil)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	assert.Equal(t, "unknown", out.Transaction)
	var checks atomic.Int32
	out, e = Execute(context.Background(), target, secret, query(command("ECHO", "private-result"), true), func() error {
		if checks.Add(1) >= 3 {
			return errors.New("revoked")
		}
		return nil
	})
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Empty(t, out.Rows)
}
func TestRealRedisPinnedGatewayAndSanitizedServerError(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "redis")
	destination := "redis.synthetic.invalid:" + strconv.Itoa(target.Port)
	loopback := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{destination: loopback})
	require.NoError(t, e)
	defer g.Close()
	host, port, e := net.SplitHostPort(g.Address())
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	target.Host = "redis.synthetic.invalid"
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	require.NoError(t, Ping(context.Background(), target, secret))
	out, e := Execute(context.Background(), target, secret, query(`["NOT_A_COMMAND","private-value"]`, false), nil)
	require.Error(t, e)
	assert.Equal(t, "ERR", out.DatabaseCode)
	assert.NotContains(t, fmt.Sprint(e), "private")
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	assert.Error(t, Ping(context.Background(), target, secret))
}
