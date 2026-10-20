package mysqlclient_test

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mysqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/mysqlfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRealMySQLAndMariaDBPAMExactHostPluginAndCredentialProof(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		t.Run(engine, func(t *testing.T) {
			target, admin := mysqlfixture.LoadPAM(t, engine)
			ctx := context.Background()
			maria := engine == "mariadb"
			name := fmt.Sprintf("pamqa_%d", time.Now().UnixNano())
			account := "'" + name + "'@'%'"
			run := func(statement string) error {
				_, e := mysqlclient.Execute(ctx, target, admin, sqlclient.Input{SQL: statement, RowLimit: 20, TimeoutSeconds: 5}, nil)
				return e
			}
			require.NoError(t, run("CREATE USER "+account+" IDENTIFIED BY 'Synthetic-PAM-Initial-233!'"))
			t.Cleanup(func() {
				require.NoError(t, run("DROP USER IF EXISTS "+account))
				require.NoError(t, run("DROP USER IF EXISTS "+account))
			})
			rows, e := mysqlclient.DiscoverPAM(ctx, target, admin, maria)
			require.NoError(t, e)
			var p pamtypes.Principal
			for _, r := range rows {
				if r.Username == name && r.Host == "%" {
					p = r
				}
			}
			require.NotEmpty(t, p.ID)
			user := target
			user.Username = name
			initial := sqlclient.Credentials{Password: "Synthetic-PAM-Initial-233!"}
			require.NoError(t, mysqlclient.VerifyPAMPassword(ctx, user, initial, p))
			bad := p
			bad.Plugin = "authentication_ldap_simple"
			assert.ErrorIs(t, mysqlclient.ResetPAMPassword(ctx, target, admin, bad, "unapplied-password", func() error { return nil }, maria), pamtypes.ErrScope)
			bad = p
			bad.Host = "localhost"
			bad.ID = pamtypes.MySQLID(bad.Username, bad.Host)
			assert.ErrorIs(t, mysqlclient.VerifyPAMPassword(ctx, user, initial, bad), pamtypes.ErrChanged)
			next := sqlclient.Credentials{Password: `Synthetic-PAM-'密码\233!`}
			require.NoError(t, mysqlclient.ResetPAMPassword(ctx, target, admin, p, next.Password, func() error { return nil }, maria))
			require.NoError(t, mysqlclient.VerifyPAMPassword(ctx, user, next, p))
			assert.Error(t, mysqlclient.VerifyPAMPassword(ctx, user, initial, p))
			after, e := mysqlclient.DiscoverPAM(ctx, target, admin, maria)
			require.NoError(t, e)
			assert.Contains(t, after, p)
			if maria {
				require.NoError(t, run("ALTER USER "+account+" IDENTIFIED VIA mysql_native_password USING PASSWORD('Synthetic-PAM-Dual-233!') OR unix_socket"))
				assert.ErrorIs(t, mysqlclient.ResetPAMPassword(ctx, target, admin, p, "unapplied-password", func() error { return nil }, true), pamtypes.ErrScope)
				inventory, err := mysqlclient.DiscoverPAM(ctx, target, admin, true)
				require.NoError(t, err)
				assert.NotContains(t, inventory, p)
				return
			}
			require.NoError(t, run("ALTER USER "+account+" ACCOUNT LOCK"))
			assert.ErrorIs(t, mysqlclient.ResetPAMPassword(ctx, target, admin, p, "unapplied-password", func() error { return nil }, maria), pamtypes.ErrChanged)
		})
	}
}
