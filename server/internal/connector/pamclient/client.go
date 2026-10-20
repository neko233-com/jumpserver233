// Package pamclient dispatches fixed account-management operations. It has no
// operator-controlled SQL/script or credential-returning API.
package pamclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mysqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlserverclient"
)

func Supports(protocol string) bool {
	return protocol == "postgresql" || protocol == "mysql" || protocol == "mariadb" || protocol == "sqlserver"
}
func Discover(ctx context.Context, protocol string, t sqlclient.Target, c sqlclient.Credentials) ([]pamtypes.Principal, error) {
	switch protocol {
	case "postgresql":
		return postgresclient.DiscoverPAM(ctx, t, c)
	case "mysql", "mariadb":
		return mysqlclient.DiscoverPAM(ctx, t, c, protocol == "mariadb")
	case "sqlserver":
		return sqlserverclient.DiscoverPAM(ctx, t, c)
	}
	return nil, pamtypes.ErrScope
}
func Reset(ctx context.Context, protocol string, t sqlclient.Target, c sqlclient.Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard) error {
	switch protocol {
	case "postgresql":
		return postgresclient.ResetPAMPassword(ctx, t, c, p, password, guard)
	case "mysql", "mariadb":
		return mysqlclient.ResetPAMPassword(ctx, t, c, p, password, guard, protocol == "mariadb")
	case "sqlserver":
		return sqlserverclient.ResetPAMPassword(ctx, t, c, p, password, guard)
	}
	return pamtypes.ErrScope
}
func Verify(ctx context.Context, protocol string, t sqlclient.Target, c sqlclient.Credentials, p pamtypes.Principal) error {
	if t.TLSMode != "verify-full" {
		return pamtypes.ErrScope
	}
	switch protocol {
	case "postgresql":
		return postgresclient.VerifyPAMPassword(ctx, t, c, p)
	case "mysql", "mariadb":
		return mysqlclient.VerifyPAMPassword(ctx, t, c, p)
	case "sqlserver":
		return sqlserverclient.VerifyPAMPassword(ctx, t, c, p)
	}
	return pamtypes.ErrScope
}
