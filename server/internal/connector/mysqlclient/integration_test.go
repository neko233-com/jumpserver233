package mysqlclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mysqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/mysqlfixture"
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

func TestRealMySQLAndMariaDBTLSBindingsReadOnlyAutocommitAndLimits(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		t.Run(engine, func(t *testing.T) {
			target, secret := mysqlfixture.Load(t, engine)
			ctx := context.Background()
			require.NoError(t, mysqlclient.Ping(ctx, target, secret))
			bad := target
			bad.ServerName = "wrong.invalid"
			require.ErrorIs(t, mysqlclient.Ping(ctx, bad, secret), sqlclient.ErrUnavailable)
			bad = target
			bad.RootCAPEM = ""
			require.ErrorIs(t, mysqlclient.Ping(ctx, bad, secret), sqlclient.ErrUnavailable)
			run := func(sql string, ro bool, params ...json.RawMessage) (sqlclient.Result, error) {
				return mysqlclient.Execute(ctx, target, secret, sqlclient.Input{SQL: sql, ReadOnly: ro, Parameters: params, RowLimit: 20, TimeoutSeconds: 5}, nil)
			}
			marker := `private-param '); DROP DATABASE qa; --`
			raw, _ := json.Marshal(marker)
			r, e := run("SELECT ?, NULL, CAST(? AS SIGNED)", true, raw, json.RawMessage("42"))
			require.NoError(t, e)
			require.Len(t, r.Rows, 1)
			assert.Equal(t, marker, *r.Rows[0][0])
			assert.Nil(t, r.Rows[0][1])
			assert.Equal(t, "42", *r.Rows[0][2])
			assert.Equal(t, "rolled_back", r.Transaction)
			table := fmt.Sprintf("query_%d", time.Now().UnixNano())
			r, e = run("CREATE TABLE "+table+" (id int PRIMARY KEY, value text) ENGINE=InnoDB", false)
			require.NoError(t, e)
			assert.Equal(t, "committed", r.Transaction)
			t.Cleanup(func() { _, _ = run("DROP TABLE IF EXISTS "+table, false) })
			_, e = run("INSERT INTO "+table+" VALUES(1,'forbidden')", true)
			assert.ErrorIs(t, e, sqlclient.ErrDenied)
			r, e = run("INSERT INTO "+table+" VALUES(1,?)", false, json.RawMessage(`"kept"`))
			require.NoError(t, e)
			assert.Equal(t, "committed", r.Transaction)
			assert.EqualValues(t, 1, r.AffectedRows)
			_, e = run("SELECT 1; DELETE FROM "+table, false)
			require.Error(t, e)
			r, e = run("SELECT COUNT(*) FROM "+table, true)
			require.NoError(t, e)
			assert.Equal(t, "1", *r.Rows[0][0])
			r, e = mysqlclient.Execute(ctx, target, secret, sqlclient.Input{SQL: "SELECT 1 UNION ALL SELECT 2", RowLimit: 1, TimeoutSeconds: 5, ReadOnly: true}, nil)
			assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
			assert.True(t, r.Truncated)
			assert.Equal(t, "rolled_back", r.Transaction)
			r, e = run("SELECT REPEAT('界',10000)", true)
			require.NoError(t, e)
			assert.True(t, r.Truncated)
			assert.LessOrEqual(t, len(*r.Rows[0][0]), sqlclient.MaxCellBytes)
			_, e = run("WITH RECURSIVE seq AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM seq WHERE n<12) SELECT REPEAT('x',500000) FROM seq", true)
			assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
			denied, e := mysqlclient.Execute(ctx, target, secret, sqlclient.Input{SQL: "INSERT INTO " + table + " VALUES(2,'denied')", RowLimit: 1, TimeoutSeconds: 5}, func() error { return sqlclient.ErrDenied })
			assert.ErrorIs(t, e, sqlclient.ErrDenied)
			assert.Equal(t, "not_started", denied.Transaction)
			short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			started := time.Now()
			r, e = mysqlclient.Execute(short, target, secret, sqlclient.Input{SQL: "SELECT SLEEP(5)", ReadOnly: true, RowLimit: 1, TimeoutSeconds: 5}, nil)
			require.Error(t, e)
			assert.Less(t, time.Since(started), 3*time.Second)
			assert.Equal(t, "rolled_back", r.Transaction)
			target.ReadOnly = true
			_, e = run("DROP TABLE "+table, false)
			assert.ErrorIs(t, e, sqlclient.ErrDenied)
			target.ReadOnly = false
			_, e = run("SELECT CAST(? AS JSON)", true, json.RawMessage(`"private-invalid-json"`))
			if e != nil {
				assert.NotContains(t, e.Error(), "private-invalid-json")
			}
		})
	}
}
func TestRealMySQLAndMariaDBNontransactionalWritesAndStoredProceduresAreReportedHonestly(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		t.Run(engine, func(t *testing.T) {
			target, secret := mysqlfixture.Load(t, engine)
			run := func(sql string, ro bool) (sqlclient.Result, error) {
				return mysqlclient.Execute(context.Background(), target, secret, sqlclient.Input{SQL: sql, ReadOnly: ro, RowLimit: 5, TimeoutSeconds: 5}, nil)
			}
			table := fmt.Sprintf("myisam_%d", time.Now().UnixNano())
			_, e := run("CREATE TABLE "+table+" (id int PRIMARY KEY) ENGINE=MyISAM", false)
			require.NoError(t, e)
			t.Cleanup(func() { _, _ = run("DROP TABLE IF EXISTS "+table, false) })
			_, e = run("INSERT INTO "+table+" VALUES(1)", false)
			require.NoError(t, e)
			r, e := run("INSERT INTO "+table+" VALUES(2),(1)", false)
			require.Error(t, e)
			assert.Equal(t, "unknown", r.Transaction)
			r, e = run("SELECT COUNT(*) FROM "+table, true)
			require.NoError(t, e)
			assert.Equal(t, "2", *r.Rows[0][0])
			procedure := fmt.Sprintf("proc_%d", time.Now().UnixNano())
			_, e = run("CREATE PROCEDURE "+procedure+"() BEGIN SELECT 1; END; DROP TABLE "+table, false)
			require.Error(t, e)
			r, e = run("SELECT COUNT(*) FROM "+table, true)
			require.NoError(t, e)
			assert.Equal(t, "2", *r.Rows[0][0])
			_, e = run("CREATE PROCEDURE "+procedure+"() BEGIN SELECT 1 AS value; END", false)
			require.NoError(t, e)
			t.Cleanup(func() { _, _ = run("DROP PROCEDURE IF EXISTS "+procedure, false) })
			_, e = run("CALL "+procedure+"()", true)
			assert.ErrorIs(t, e, sqlclient.ErrDenied)
			r, e = run("CALL "+procedure+"()", false)
			require.NoError(t, e)
			assert.Equal(t, "server_managed", r.Transaction)
		})
	}
}
func TestRealMySQLAndMariaDBThroughPinnedGateway(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		t.Run(engine, func(t *testing.T) {
			target, secret := mysqlfixture.Load(t, engine)
			dest := postgresfixture.LoopbackForward(t, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
			gateway, e := sshgateway.Start("127.0.0.1:0", map[string]string{"mysql.synthetic.invalid:3306": dest})
			require.NoError(t, e)
			defer gateway.Close()
			host, port, _ := net.SplitHostPort(gateway.Address())
			n, _ := strconv.Atoi(port)
			target.Gateways = []sshclient.Hop{{Target: sshclient.Target{Host: host, Port: n, Username: sshgateway.Username, HostKeyFingerprint: gateway.Fingerprint}, Credentials: sshclient.Credentials{Password: sshgateway.Password}}}
			target.Host = "mysql.synthetic.invalid"
			target.Port = 3306
			r, e := mysqlclient.Execute(context.Background(), target, secret, sqlclient.Input{SQL: "SELECT DATABASE()", ReadOnly: true, RowLimit: 1, TimeoutSeconds: 5}, nil)
			require.NoError(t, e)
			assert.Equal(t, "qa", *r.Rows[0][0])
			require.Eventually(t, func() bool { return gateway.Active() == 0 }, 3*time.Second, 10*time.Millisecond)
			target.Gateways[0].Target.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
			assert.Error(t, mysqlclient.Ping(context.Background(), target, secret))
		})
	}
}
