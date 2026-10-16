package mongodbclient

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

func TestRealMongoDBTLSNullMissingExtendedTypesAndReadonly(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "mongodb")
	require.NoError(t, Ping(context.Background(), target, secret))
	bad := target
	bad.ServerName = "untrusted.invalid"
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.RootCAPEM = ""
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.AuthDatabase = "wrong"
	assert.Error(t, Ping(context.Background(), bad, secret))
	raw := `{"aggregate":1,"pipeline":[{"$documents":[{"message":"private-中文","optional":null,"precise":{"$numberLong":"9223372036854775807"},"binary":{"$binary":{"base64":"AP8=","subType":"00"}}},{"message":"missing optional"}]}],"cursor":{}}`
	out, e := Execute(context.Background(), target, secret, query(raw, true), nil)
	require.NoError(t, e)
	require.Len(t, out.Rows, 2)
	assert.Equal(t, "private-中文", *out.Rows[0][0])
	assert.Nil(t, out.Rows[0][1])
	assert.Equal(t, "9223372036854775807", *out.Rows[0][2])
	assert.Contains(t, *out.Rows[0][3], "$binary")
	assert.Contains(t, out.MissingCells, [2]int{1, 1})
	assert.Equal(t, "read_only", out.Transaction)
	target.ReadOnly = true
	out, e = Execute(context.Background(), target, secret, query(`{"insert":"must_not_exist","documents":[{"private":"value"}]}`, false), nil)
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "not_started", out.Transaction)
}
func TestRealMongoDBCursorsWritesAndPartialInsertHasNoClaimedRollback(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "mongodb")
	collection := "jq_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	defer Execute(context.Background(), target, secret, query(fmt.Sprintf(`{"drop":%q}`, collection), false), nil)
	docs := make([]map[string]any, 1005)
	for i := range docs {
		docs[i] = map[string]any{"_id": i, "value": "row"}
	}
	raw, _ := json.Marshal(struct {
		Insert    string           `json:"insert"`
		Documents []map[string]any `json:"documents"`
	}{collection, docs})
	out, e := Execute(context.Background(), target, secret, query(string(raw), false), nil)
	require.NoError(t, e)
	assert.Equal(t, "server_managed", out.Transaction)
	assert.EqualValues(t, 1005, out.AffectedRows)
	in := query(fmt.Sprintf(`{"find":%q,"sort":{"_id":1}}`, collection), true)
	in.RowLimit = 1500
	out, e = Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	require.Len(t, out.Rows, 1005)
	assert.Equal(t, "1004", *out.Rows[1004][0])
	out, e = Execute(context.Background(), target, secret, query(fmt.Sprintf(`{"insert":%q,"documents":[{"_id":2000,"value":"private"},{"_id":2000,"value":"private"}]}`, collection), false), nil)
	require.Error(t, e)
	assert.Equal(t, "unknown", out.Transaction)
	assert.Equal(t, "11000", out.DatabaseCode)
	assert.NotContains(t, e.Error(), "private")
	out, e = Execute(context.Background(), target, secret, query(fmt.Sprintf(`{"count":%q,"query":{"_id":2000}}`, collection), true), nil)
	require.NoError(t, e)
	assert.Equal(t, "1", *out.Rows[0][0])
	in.RowLimit = 1
	_, e = Execute(context.Background(), target, secret, in, nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	out, e = Execute(ctx, target, secret, query(fmt.Sprintf(`{"find":%q,"filter":{"$where":"function(){var t=Date.now();while(Date.now()-t<2000){};return true;}"}}`, collection), false), nil)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	assert.Equal(t, "unknown", out.Transaction)
}
func TestRealMongoDBLimitsAuthorizationAndPinnedGateway(t *testing.T) {
	target, secret := nosqlfixture.Load(t, "mongodb")
	in := query(`{"aggregate":1,"pipeline":[{"$documents":[{"x":"abc"},{"x":"def"}]}],"cursor":{}}`, true)
	in.RowLimit = 1
	_, e := Execute(context.Background(), target, secret, in, nil)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	out, e := Execute(context.Background(), target, secret, query(`{"ping":1}`, true), func() error { return errors.New("denied") })
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Equal(t, "not_started", out.Transaction)
	var checks atomic.Int32
	out, e = Execute(context.Background(), target, secret, query(`{"ping":1}`, true), func() error {
		if checks.Add(1) >= 3 {
			return errors.New("revoked")
		}
		return nil
	})
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Empty(t, out.Rows)
	destination := "mongodb.synthetic.invalid:" + strconv.Itoa(target.Port)
	loopback := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	g, e := sshgateway.Start("127.0.0.1:0", map[string]string{destination: loopback})
	require.NoError(t, e)
	defer g.Close()
	host, port, e := net.SplitHostPort(g.Address())
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	target.Host = "mongodb.synthetic.invalid"
	target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: g.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
	require.NoError(t, Ping(context.Background(), target, secret))
	target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	assert.Error(t, Ping(context.Background(), target, secret))
}
