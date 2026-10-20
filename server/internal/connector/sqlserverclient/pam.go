package sqlserverclient

import (
	"context"
	"database/sql"
	"encoding/hex"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"strings"
	"time"
	"unicode/utf16"
)

func DiscoverPAM(ctx context.Context, t Target, c Credentials) ([]pamtypes.Principal, error) {
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
	rows, e := conn.QueryContext(ctx, "SELECT TOP (1001) name, CONVERT(varchar(172),sid,2), is_disabled FROM sys.sql_logins ORDER BY principal_id")
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	defer rows.Close()
	out := []pamtypes.Principal{}
	for rows.Next() {
		var p pamtypes.Principal
		var disabled bool
		if rows.Scan(&p.Username, &p.ID, &disabled) != nil || !pamtypes.Text(p.Username, 512) || len(p.ID) > 172 || len(out) >= pamtypes.MaxPrincipals {
			return nil, pamtypes.ErrUnavailable
		}
		sid, e := hex.DecodeString(p.ID)
		if e != nil || len(sid) == 0 {
			return nil, pamtypes.ErrUnavailable
		}
		p.Scope = "instance"
		p.Enabled = !disabled
		out = append(out, p)
	}
	if rows.Err() != nil {
		return nil, pamtypes.ErrUnavailable
	}
	return out, nil
}
func VerifyPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal) error {
	if t.TLSMode != "verify-full" {
		return pamtypes.ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return pamtypes.ErrUnavailable
	}
	defer db.Close()
	defer conn.Close()
	var sid string
	if conn.QueryRowContext(ctx, "SELECT CONVERT(varchar(172),SUSER_SID(),2)").Scan(&sid) != nil {
		return pamtypes.ErrUnavailable
	}
	if !strings.EqualFold(sid, p.ID) {
		return pamtypes.ErrChanged
	}
	return nil
}
func ResetPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard) error {
	if t.TLSMode != "verify-full" {
		return pamtypes.ErrScope
	}
	sid, e := hex.DecodeString(p.ID)
	if e != nil || !p.Enabled || len(sid) == 0 || len(sid) > 86 || !pamtypes.Text(p.Username, 512) || len(utf16.Encode([]rune(p.Username))) > 128 || p.Scope != "instance" || p.Host != "" || p.Plugin != "" || !pamtypes.ValidPassword(password) || len(utf16.Encode([]rune(password))) > 128 {
		return pamtypes.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return pamtypes.ErrUnavailable
	}
	defer db.Close()
	defer conn.Close()
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	// QUOTENAME applies server-side identifier/literal quoting to bound values.
	// The fixed batch never appears in user SQL history or returns diagnostics.
	const batch = `SET XACT_ABORT ON;
BEGIN TRANSACTION;
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name=@login AND sid=@sid AND is_disabled=0) THROW 51000, 'principal_changed', 1;
DECLARE @statement nvarchar(max)=N'ALTER LOGIN '+QUOTENAME(@login)+N' WITH PASSWORD = N'+QUOTENAME(@password,CHAR(39));
IF @statement IS NULL THROW 51000, 'invalid_principal', 1;
EXEC sys.sp_executesql @statement;
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name=@login AND sid=@sid AND is_disabled=0) THROW 51000, 'principal_changed', 1;
COMMIT TRANSACTION;`
	if _, e = conn.ExecContext(ctx, batch, sql.Named("login", p.Username), sql.Named("sid", sid), sql.Named("password", password)); e != nil {
		return pamtypes.ErrUnavailable
	}
	return nil
}
