package postgresclient_test

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRealPostgresPAMRotationPinnedOIDAndRevokedGuard(t *testing.T) {
	target, admin := postgresfixture.LoadPAM(t)
	ctx := context.Background()
	name := fmt.Sprintf("pamqa_%d", time.Now().UnixNano())
	run := func(statement string) error {
		_, e := postgresclient.Execute(ctx, target, admin, postgresclient.Input{SQL: statement, RowLimit: 20, TimeoutSeconds: 5}, nil)
		return e
	}
	require.NoError(t, run("CREATE ROLE "+name+" LOGIN PASSWORD 'Synthetic-PAM-Initial-233!'"))
	t.Cleanup(func() {
		require.NoError(t, run("DROP ROLE IF EXISTS "+name))
		require.NoError(t, run("DROP ROLE IF EXISTS "+name))
	})
	rows, e := postgresclient.DiscoverPAM(ctx, target, admin)
	require.NoError(t, e)
	var principal pamtypes.Principal
	for _, p := range rows {
		if p.Username == name {
			principal = p
		}
	}
	require.NotEmpty(t, principal.ID)
	require.True(t, principal.Enabled)
	user := target
	user.Username = name
	initial := postgresclient.Credentials{Password: "Synthetic-PAM-Initial-233!"}
	require.NoError(t, postgresclient.VerifyPAMPassword(ctx, user, initial, principal))
	denied, cancel := context.WithCancel(ctx)
	cancel()
	assert.ErrorIs(t, postgresclient.ResetPAMPassword(denied, target, admin, principal, "unapplied-password", func() error { return nil }), context.Canceled)
	bad := principal
	bad.ID = "1"
	assert.ErrorIs(t, postgresclient.ResetPAMPassword(ctx, target, admin, bad, "unapplied-password", func() error { return nil }), pamtypes.ErrChanged)
	next := postgresclient.Credentials{Password: "Synthetic-PAM-Next-密码'233!"}
	require.NoError(t, postgresclient.ResetPAMPassword(ctx, target, admin, principal, next.Password, func() error { return nil }))
	require.NoError(t, postgresclient.VerifyPAMPassword(ctx, user, next, principal))
	assert.Error(t, postgresclient.VerifyPAMPassword(ctx, user, initial, principal))
	assert.ErrorIs(t, postgresclient.VerifyPAMPassword(ctx, user, next, bad), pamtypes.ErrChanged)
	target.TLSMode = "disable"
	_, e = postgresclient.DiscoverPAM(ctx, target, admin)
	assert.ErrorIs(t, e, pamtypes.ErrScope)
}
