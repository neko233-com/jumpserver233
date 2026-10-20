package mysqlclient

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPAMMySQLQuotingAndPluginScope(t *testing.T) {
	assert.Equal(t, `'one''two\three'`, mysqlAccountLiteral(`one'two\three`))
	p := pamtypes.Principal{Username: "operator", Host: "%", ID: pamtypes.MySQLID("operator", "%"), Scope: "server", Plugin: "mysql_native_password", Enabled: true}
	target := Target{}
	target.TLSMode = "disable"
	_, e := DiscoverPAM(t.Context(), target, Credentials{}, false)
	assert.ErrorIs(t, e, pamtypes.ErrScope)
	target.TLSMode = "verify-full"
	p.Plugin = "authentication_ldap_simple"
	assert.ErrorIs(t, ResetPAMPassword(t.Context(), target, Credentials{}, p, "next-password", func() error { return nil }, false), pamtypes.ErrScope)
	p.Plugin = "caching_sha2_password"
	assert.ErrorIs(t, ResetPAMPassword(t.Context(), target, Credentials{}, p, "next-password", func() error { return nil }, true), pamtypes.ErrScope)
	p.ID = "wrong"
	assert.ErrorIs(t, ResetPAMPassword(t.Context(), target, Credentials{}, p, "next-password", func() error { return nil }, false), pamtypes.ErrInvalid)
}
