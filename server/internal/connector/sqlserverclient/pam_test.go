package sqlserverclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/sqlserverfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestPAMSQLServerRejectsInvalidSIDUnicodeLengthAndTLS(t *testing.T) {
	target := Target{}
	_, e := DiscoverPAM(t.Context(), target, Credentials{})
	assert.ErrorIs(t, e, pamtypes.ErrScope)
	target.TLSMode = "verify-full"
	p := pamtypes.Principal{Username: "operator", ID: "01234567", Scope: "instance", Enabled: true}
	for _, password := range []string{"", strings.Repeat("😀", 65), "bad\npassword"} {
		assert.ErrorIs(t, ResetPAMPassword(t.Context(), target, Credentials{}, p, password, func() error { return nil }), pamtypes.ErrInvalid)
	}
	p.ID = "nonhex"
	assert.ErrorIs(t, ResetPAMPassword(t.Context(), target, Credentials{}, p, "next-password", func() error { return nil }), pamtypes.ErrInvalid)
}
func TestRealSQLServerPAMSIDAndBoundUnicodePassword(t *testing.T) {
	target, admin := sqlserverfixture.LoadPAM(t)
	ctx := context.Background()
	name := fmt.Sprintf("pamqa_%d", time.Now().UnixNano())
	run := func(statement string) error {
		_, e := Execute(ctx, target, admin, sqlclient.Input{SQL: statement, RowLimit: 20, TimeoutSeconds: 5}, nil)
		return e
	}
	require.NoError(t, run("CREATE LOGIN ["+name+"] WITH PASSWORD='Synthetic-PAM-Initial-233!', CHECK_POLICY=OFF"))
	drop := "IF EXISTS(SELECT 1 FROM sys.sql_logins WHERE name='" + name + "') DROP LOGIN [" + name + "]"
	t.Cleanup(func() { require.NoError(t, run(drop)); require.NoError(t, run(drop)) })
	rows, e := DiscoverPAM(ctx, target, admin)
	require.NoError(t, e)
	var p pamtypes.Principal
	for _, row := range rows {
		if row.Username == name {
			p = row
		}
	}
	require.NotEmpty(t, p.ID)
	user := target
	user.Username = name
	initial := Credentials{Password: "Synthetic-PAM-Initial-233!"}
	require.NoError(t, VerifyPAMPassword(ctx, user, initial, p))
	bad := p
	bad.ID = "01020304"
	assert.Error(t, ResetPAMPassword(ctx, target, admin, bad, "unapplied-password", func() error { return nil }))
	require.NoError(t, VerifyPAMPassword(ctx, user, initial, p))
	next := Credentials{Password: "Synthetic-PAM-'密码233!"}
	require.NoError(t, ResetPAMPassword(ctx, target, admin, p, next.Password, func() error { return nil }))
	require.NoError(t, VerifyPAMPassword(ctx, user, next, p))
	assert.Error(t, VerifyPAMPassword(ctx, user, initial, p))
	assert.ErrorIs(t, VerifyPAMPassword(ctx, user, next, bad), pamtypes.ErrChanged)
}
