package mysqlclient

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"strings"
	"time"
)

func DiscoverPAM(ctx context.Context, t Target, c Credentials, maria bool) ([]pamtypes.Principal, error) {
	if t.TLSMode != "verify-full" {
		return nil, pamtypes.ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	defer db.Close()
	defer conn.Close()
	// mysql.user exposes the logical user@host identity on MySQL and MariaDB.
	// Do not select authentication strings or password hashes.
	query := "SELECT User, Host, plugin, account_locked FROM mysql.user WHERE User <> '' AND plugin IN ('mysql_native_password','caching_sha2_password','sha256_password') ORDER BY User, Host LIMIT 1001"
	if maria {
		query = "SELECT u.User,u.Host,u.plugin,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(p.Priv,'$.account_locked')),'false') FROM mysql.user u JOIN mysql.global_priv p ON u.User=p.User AND u.Host=p.Host WHERE u.User<>'' AND u.is_role='N' AND u.plugin='mysql_native_password' AND COALESCE(JSON_LENGTH(JSON_EXTRACT(p.Priv,'$.auth_or')),0)=0 ORDER BY u.User,u.Host LIMIT 1001"
	}
	rows, e := conn.QueryContext(ctx, query)
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	defer rows.Close()
	out := []pamtypes.Principal{}
	for rows.Next() {
		var user, host, plugin, locked string
		if rows.Scan(&user, &host, &plugin, &locked) != nil || !pamtypes.Text(user, 128) || !pamtypes.Text(host, 255) || len(out) >= pamtypes.MaxPrincipals {
			return nil, pamtypes.ErrUnavailable
		}
		out = append(out, pamtypes.Principal{Username: user, Host: host, ID: pamtypes.MySQLID(user, host), Plugin: plugin, Scope: "server", Enabled: locked == "N" || locked == "false" || locked == "0"})
	}
	if rows.Err() != nil {
		return nil, pamtypes.ErrUnavailable
	}
	return out, nil
}
func mysqlAccountLiteral(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
func VerifyPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal) error {
	if t.TLSMode != "verify-full" {
		return pamtypes.ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// Authentication proof must not require access to the operator's selected
	// application schema. Every authenticated MySQL-family account can read its
	// information_schema metadata without granting new privileges.
	t.Database = "information_schema"
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return pamtypes.ErrUnavailable
	}
	defer db.Close()
	defer conn.Close()
	var current string
	if conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&current) != nil {
		return pamtypes.ErrUnavailable
	}
	if current != p.Username+"@"+p.Host {
		return pamtypes.ErrChanged
	}
	return nil
}
func ResetPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard, maria bool) error {
	if t.TLSMode != "verify-full" {
		return pamtypes.ErrScope
	}
	if !p.Enabled || !pamtypes.Text(p.Username, 128) || !pamtypes.Text(p.Host, 255) || p.Scope != "server" || p.ID != pamtypes.MySQLID(p.Username, p.Host) || !pamtypes.ValidPassword(password) {
		return pamtypes.ErrInvalid
	}
	if p.Plugin != "mysql_native_password" && p.Plugin != "caching_sha2_password" && p.Plugin != "sha256_password" || maria && p.Plugin != "mysql_native_password" {
		return pamtypes.ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e := pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return pamtypes.ErrUnavailable
	}
	defer db.Close()
	defer conn.Close()
	// Fix quoting on this disposable connection. This cannot change another
	// session or the server's global SQL mode, including on MariaDB.
	if _, e = conn.ExecContext(ctx, "SET SESSION sql_mode = CONCAT(@@SESSION.sql_mode, ',NO_BACKSLASH_ESCAPES')"); e != nil {
		return pamtypes.ErrUnavailable
	}
	var plugin, locked string
	var secondary bool
	query := "SELECT plugin,account_locked,COALESCE(JSON_CONTAINS_PATH(User_attributes,'one','$.additional_password'),0) FROM mysql.user WHERE User=? AND Host=?"
	if maria {
		query = "SELECT u.plugin,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(p.Priv,'$.account_locked')),'false'),COALESCE(JSON_LENGTH(JSON_EXTRACT(p.Priv,'$.auth_or')),0)>0 FROM mysql.user u JOIN mysql.global_priv p ON u.User=p.User AND u.Host=p.Host WHERE u.User=? AND u.Host=? AND u.is_role='N'"
	} else {
		// MySQL 5.7 has no secondary-password feature or User_attributes column.
		// Inspect only column metadata; never fetch authentication material.
		var attributes int
		if conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='mysql' AND TABLE_NAME='user' AND COLUMN_NAME='User_attributes'").Scan(&attributes) != nil {
			return pamtypes.ErrUnavailable
		}
		if attributes == 0 {
			query = "SELECT plugin,account_locked,0 FROM mysql.user WHERE User=? AND Host=?"
		} else if attributes != 1 {
			return pamtypes.ErrScope
		}
	}
	if conn.QueryRowContext(ctx, query, p.Username, p.Host).Scan(&plugin, &locked, &secondary) != nil {
		return pamtypes.ErrChanged
	}
	if plugin != p.Plugin || locked != "N" && locked != "false" && locked != "0" {
		return pamtypes.ErrChanged
	}
	if secondary {
		return pamtypes.ErrScope
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	// Password DDL is kept outside the general query/audit API. Driver logging
	// is disabled and errors are replaced with fixed codes. MySQL owns DDL
	// commit semantics; callers must authenticate both staged and old secrets.
	statement := "ALTER USER " + mysqlAccountLiteral(p.Username) + "@" + mysqlAccountLiteral(p.Host) + " IDENTIFIED WITH " + p.Plugin + " BY " + mysqlAccountLiteral(password)
	if maria {
		statement = "ALTER USER " + mysqlAccountLiteral(p.Username) + "@" + mysqlAccountLiteral(p.Host) + " IDENTIFIED VIA mysql_native_password USING PASSWORD(" + mysqlAccountLiteral(password) + ")"
	}
	if _, e = conn.ExecContext(ctx, statement); e != nil {
		return pamtypes.ErrUnavailable
	}
	return nil
}
