package postgresclient

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/neko233-com/jumpserver233/server/internal/connector/pamtypes"
	"golang.org/x/text/secure/precis"
)

func pamConnection(ctx context.Context, t Target, c Credentials) (*pgconn.PgConn, error) {
	if t.TLSMode != "verify-full" {
		return nil, pamtypes.ErrScope
	}
	cfg, e := connectionConfig(t, c)
	if e != nil {
		return nil, pamtypes.ErrInvalid
	}
	conn, e := pgconn.ConnectConfig(ctx, cfg)
	if e != nil {
		return nil, pamtypes.ErrUnavailable
	}
	return conn, nil
}
func DiscoverPAM(ctx context.Context, t Target, c Credentials) ([]pamtypes.Principal, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, e := pamConnection(ctx, t, c)
	if e != nil {
		return nil, e
	}
	defer closePAMConnection(conn)
	r := conn.ExecParams(ctx, "SELECT rolname, oid::text, rolcanlogin::text FROM pg_catalog.pg_roles WHERE rolcanlogin ORDER BY oid LIMIT 1001", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) > pamtypes.MaxPrincipals {
		return nil, pamtypes.ErrUnavailable
	}
	rows := make([]pamtypes.Principal, 0, len(r.Rows))
	for _, v := range r.Rows {
		if len(v) != 3 {
			return nil, pamtypes.ErrUnavailable
		}
		id, e := strconv.ParseUint(string(v[1]), 10, 32)
		if e != nil || id == 0 || !pamtypes.Text(string(v[0]), 63) {
			return nil, pamtypes.ErrUnavailable
		}
		rows = append(rows, pamtypes.Principal{Username: string(v[0]), ID: string(v[1]), Scope: "cluster", Enabled: string(v[2]) == "true"})
	}
	return rows, nil
}
func scramVerifier(password string) (string, error) {
	if !pamtypes.ValidPassword(password) {
		return "", pamtypes.ErrInvalid
	}
	normalized, e := precis.OpaqueString.String(password)
	if e != nil {
		normalized = password
	}
	salt := make([]byte, 16)
	if _, e = rand.Read(salt); e != nil {
		return "", e
	}
	salted, e := pbkdf2.Key(sha256.New, normalized, salt, 4096, 32)
	if e != nil {
		return "", pamtypes.ErrInvalid
	}
	h := hmac.New(sha256.New, salted)
	h.Write([]byte("Client Key"))
	stored := sha256.Sum256(h.Sum(nil))
	h = hmac.New(sha256.New, salted)
	h.Write([]byte("Server Key"))
	server := h.Sum(nil)
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$4096:%s$%s:%s", b64(salt), b64(stored[:]), b64(server)), nil
}
func ResetPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal, password string, guard pamtypes.Guard) error {
	if !p.Enabled || !pamtypes.Text(p.Username, 63) || p.Scope != "cluster" || p.Host != "" || p.Plugin != "" || !pamtypes.ValidPassword(password) {
		return pamtypes.ErrInvalid
	}
	oid, e := strconv.ParseUint(p.ID, 10, 32)
	if e != nil || oid == 0 {
		return pamtypes.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	conn, e := pamConnection(ctx, t, c)
	if e != nil {
		return e
	}
	defer closePAMConnection(conn)
	if _, e = conn.Exec(ctx, "BEGIN").ReadAll(); e != nil {
		return pamtypes.ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "ROLLBACK").ReadAll()
	}()
	check := func() error {
		r := conn.ExecParams(ctx, "SELECT oid::text FROM pg_catalog.pg_roles WHERE rolname=$1 AND rolcanlogin", [][]byte{[]byte(p.Username)}, nil, nil, nil).Read()
		if r.Err != nil {
			return pamtypes.ErrUnavailable
		}
		if len(r.Rows) != 1 || len(r.Rows[0]) != 1 || string(r.Rows[0][0]) != p.ID {
			return pamtypes.ErrChanged
		}
		return nil
	}
	if e = check(); e != nil {
		return e
	}
	verifier, e := scramVerifier(password)
	if e != nil {
		return e
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	// The DDL contains only a salted verifier, never the plaintext password.
	statement := "ALTER ROLE \"" + strings.ReplaceAll(p.Username, "\"", "\"\"") + "\" PASSWORD '" + verifier + "'"
	if _, e = conn.Exec(ctx, statement).ReadAll(); e != nil {
		return pamtypes.ErrUnavailable
	}
	if e = check(); e != nil {
		return e
	}
	if e = pamtypes.Check(ctx, guard); e != nil {
		return e
	}
	if _, e = conn.Exec(ctx, "COMMIT").ReadAll(); e != nil {
		return pamtypes.ErrUnavailable
	}
	return nil
}
func closePAMConnection(conn *pgconn.PgConn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
func VerifyPAMPassword(ctx context.Context, t Target, c Credentials, p pamtypes.Principal) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, e := pamConnection(ctx, t, c)
	if e != nil {
		return e
	}
	defer closePAMConnection(conn)
	r := conn.ExecParams(ctx, "SELECT oid::text FROM pg_catalog.pg_roles WHERE rolname=current_user", nil, nil, nil, nil).Read()
	if r.Err != nil {
		return pamtypes.ErrUnavailable
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 1 || string(r.Rows[0][0]) != p.ID {
		return pamtypes.ErrChanged
	}
	return nil
}
