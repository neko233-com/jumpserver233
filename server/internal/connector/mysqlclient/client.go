// Package mysqlclient executes one SQL statement on a disposable,
// vault-authenticated MySQL/MariaDB connection.
package mysqlclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type Target = sqlclient.Target
type Credentials = sqlclient.Credentials
type Input = sqlclient.Input
type Result = sqlclient.Result

const maxWireBytes = 4 * sqlclient.MaxResultBytes

type quietLogger struct{}

func (quietLogger) Print(...any) {}

type wireBudget struct {
	remaining atomic.Int64
	exceeded  atomic.Bool
}
type budgetConnection struct {
	net.Conn
	budget *wireBudget
}

func (c *budgetConnection) Read(p []byte) (int, error) {
	left := c.budget.remaining.Load()
	if left <= 0 {
		c.budget.exceeded.Store(true)
		_ = c.Conn.Close()
		return 0, sqlclient.ErrResultLimit
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, e := c.Conn.Read(p)
	c.budget.remaining.Add(-int64(n))
	return n, e
}
func config(target Target, secret Credentials, budget *wireBudget) (*mysql.Config, error) {
	if sqlclient.ValidateSettings(target.Settings) != nil || target.Host == "" || target.Username == "" || target.Port < 1 || target.Port > 65535 || secret.Password == "" {
		return nil, sqlclient.ErrInvalid
	}
	c := mysql.NewConfig()
	c.User = target.Username
	c.Passwd = secret.Password
	c.DBName = target.Database
	c.Net = "tcp"
	c.Addr = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	c.Timeout = 5 * time.Second
	c.MaxAllowedPacket = sqlclient.MaxParameterBytes + sqlclient.MaxSQLBytes + 1024
	c.Logger = quietLogger{}
	c.InterpolateParams = false
	c.MultiStatements = false
	c.AllowAllFiles = false
	c.AllowCleartextPasswords = false
	c.AllowOldPasswords = false
	c.AllowFallbackToPlaintext = false
	c.CheckConnLiveness = false
	c.Params = map[string]string{"sql_mode": "'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'"}
	c.ConnectionAttributes = "program_name:jumpserver233"
	c.ParseTime = false
	if target.TLSMode == "verify-full" {
		name := target.ServerName
		if name == "" {
			name = target.Host
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
		if target.RootCAPEM != "" {
			pool, e := x509.SystemCertPool()
			if e != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(target.RootCAPEM)) {
				return nil, sqlclient.ErrInvalid
			}
			tc.RootCAs = pool
		}
		c.TLS = tc
	}
	c.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		raw, e := sshclient.DialTunnel(ctx, target.Gateways, c.Addr, 5*time.Second)
		if e != nil {
			return nil, e
		}
		return &budgetConnection{Conn: raw, budget: budget}, nil
	}
	return c, nil
}
func open(ctx context.Context, target Target, secret Credentials, budget *wireBudget) (*sql.DB, *sql.Conn, error) {
	budget.remaining.Store(maxWireBytes)
	c, e := config(target, secret, budget)
	if e != nil {
		return nil, nil, e
	}
	connector, e := mysql.NewConnector(c)
	if e != nil {
		return nil, nil, sqlclient.ErrInvalid
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	conn, e := db.Conn(ctx)
	if e != nil {
		db.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, sqlclient.ErrUnavailable
	}
	return db, conn, nil
}
func Ping(ctx context.Context, target Target, secret Credentials) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	db, conn, e := open(ctx, target, secret, &wireBudget{})
	if e != nil {
		return e
	}
	defer db.Close()
	defer conn.Close()
	if e = conn.PingContext(ctx); e != nil {
		return sqlclient.ErrUnavailable
	}
	return nil
}
func bind(input []json.RawMessage) ([]any, error) {
	out := make([]any, len(input))
	for i, p := range input {
		var v any
		decoder := json.NewDecoder(strings.NewReader(string(p)))
		decoder.UseNumber()
		if decoder.Decode(&v) != nil {
			return nil, sqlclient.ErrInvalid
		}
		switch value := v.(type) {
		case nil:
			out[i] = nil
		case string:
			out[i] = value
		case bool:
			out[i] = value
		case json.Number:
			out[i] = string(value)
		default:
			out[i] = string(p)
		}
	}
	return out, nil
}
func readOnlyStatement(redacted string) bool {
	words := strings.FieldsFunc(redacted, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_') })
	if len(words) == 0 {
		return false
	}
	switch strings.ToUpper(words[0]) {
	case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "WITH", "HELP":
		return true
	}
	return false
}
func Execute(parent context.Context, target Target, secret Credentials, in Input, authorize func() error) (out Result, returned error) {
	started := time.Now()
	out = Result{Columns: []sqlclient.Column{}, Rows: [][]*string{}, ReadOnly: target.ReadOnly || in.ReadOnly, Transaction: "not_started"}
	defer func() { out.DurationMS = time.Since(started).Milliseconds() }()
	in.Dialect = "mysql"
	if sqlclient.ValidateInput(in) != nil {
		return out, sqlclient.ErrInvalid
	}
	redacted, _ := sqlclient.AuditMySQL(in.SQL)
	if out.ReadOnly && !readOnlyStatement(redacted) {
		out.ErrorCode = "read_only"
		return out, sqlclient.ErrDenied
	}
	args, e := bind(in.Parameters)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	budget := &wireBudget{}
	db, conn, e := open(ctx, target, secret, budget)
	if e != nil {
		out.ErrorCode = "connection_failed"
		if ctx.Err() != nil {
			out.ErrorCode = "cancelled"
		}
		return out, e
	}
	defer db.Close()
	defer conn.Close()
	var tx *sql.Tx
	if out.ReadOnly {
		tx, e = conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			out.ErrorCode = "connection_failed"
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			return out, sqlclient.ErrUnavailable
		}
		out.Transaction = "rolled_back"
		defer tx.Rollback()
	} else {
		if _, e = conn.ExecContext(ctx, "SET autocommit = 1"); e != nil {
			out.ErrorCode = "connection_failed"
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			return out, sqlclient.ErrUnavailable
		}
	}
	if authorize != nil {
		if e = authorize(); e != nil {
			out.ErrorCode = "access_revoked"
			return out, sqlclient.ErrDenied
		}
	}
	var statement *sql.Stmt
	if tx != nil {
		statement, e = tx.PrepareContext(ctx, in.SQL)
	} else {
		statement, e = conn.PrepareContext(ctx, in.SQL)
	}
	textOnly := false
	if e != nil {
		if textFallback(e, len(args)) {
			textOnly = true
		} else {
			return queryError(out, e, ctx, budget)
		}
	}
	if statement != nil {
		defer statement.Close()
	}
	if !out.ReadOnly {
		out.Transaction = "unknown"
	}
	var rows *sql.Rows
	if textOnly {
		if tx != nil {
			rows, e = tx.QueryContext(ctx, in.SQL)
		} else {
			rows, e = conn.QueryContext(ctx, in.SQL)
		}
	} else {
		rows, e = statement.QueryContext(ctx, args...)
	}
	if e != nil {
		return queryError(out, e, ctx, budget)
	}
	defer rows.Close()
	columns, e := rows.ColumnTypes()
	if e != nil {
		return queryError(out, e, ctx, budget)
	}
	for _, column := range columns {
		out.Columns = append(out.Columns, sqlclient.Column{Name: column.Name(), DatabaseType: column.DatabaseTypeName()})
	}
	total, cells := 0, 0
	for rows.Next() {
		if len(out.Rows) >= in.RowLimit || cells+len(columns) > sqlclient.MaxResultCells {
			out.Truncated = true
			out.ErrorCode = "result_limit"
			cancel()
			return out, sqlclient.ErrResultLimit
		}
		cells += len(columns)
		raw := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if e = rows.Scan(dest...); e != nil {
			return queryError(out, e, ctx, budget)
		}
		row := make([]*string, len(columns))
		for i, v := range raw {
			if v == nil {
				continue
			}
			var value string
			switch typed := v.(type) {
			case []byte:
				if utf8.Valid(typed) {
					value = string(typed)
				} else {
					if len(typed) > sqlclient.MaxCellBytes/2 {
						typed = typed[:sqlclient.MaxCellBytes/2]
						out.Truncated = true
					}
					value = "0x" + hex.EncodeToString(typed)
				}
			default:
				value = fmt.Sprint(typed)
			}
			if len(value) > sqlclient.MaxCellBytes {
				out.Truncated = true
				value = value[:sqlclient.MaxCellBytes]
				for !utf8.ValidString(value) && len(value) > 0 {
					value = value[:len(value)-1]
				}
			}
			total += len(value)
			if total > sqlclient.MaxResultBytes {
				out.Truncated = true
				out.ErrorCode = "result_limit"
				cancel()
				return out, sqlclient.ErrResultLimit
			}
			row[i] = &value
		}
		out.Rows = append(out.Rows, row)
	}
	if e = rows.Err(); e != nil {
		return queryError(out, e, ctx, budget)
	}
	if e = rows.Close(); e != nil {
		return queryError(out, e, ctx, budget)
	}
	if !out.ReadOnly {
		out.Transaction = "committed"
		if len(strings.Fields(redacted)) > 0 && strings.EqualFold(strings.Fields(redacted)[0], "CALL") {
			out.Transaction = "server_managed"
		}
	}
	out.AffectedRows = int64(len(out.Rows))
	if len(columns) == 0 && !out.ReadOnly {
		var count int64
		known := true
		if e = conn.QueryRowContext(ctx, "SELECT ROW_COUNT()").Scan(&count); e == nil && count >= 0 {
			out.AffectedRows = count
		} else {
			known = false
		}
		out.AffectedRowsKnown = &known
	}
	if authorize != nil {
		if e = authorize(); e != nil {
			out.Rows = nil
			out.ErrorCode = "access_revoked"
			return out, sqlclient.ErrDenied
		}
	}
	if tx != nil {
		if e = tx.Rollback(); e != nil {
			out.ErrorCode = "query_failed"
			return out, errors.New("database rollback failed")
		}
	}
	return out, nil
}
func queryError(out Result, e error, ctx context.Context, budget *wireBudget) (Result, error) {
	out.ErrorCode = "query_failed"
	if budget.exceeded.Load() {
		out.ErrorCode = "result_limit"
		out.Truncated = true
		return out, sqlclient.ErrResultLimit
	}
	var remote *mysql.MySQLError
	if errors.As(e, &remote) {
		out.SQLState = string(remote.SQLState[:])
	}
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	return out, errors.New("database query failed")
}

// A failed preparation has not executed the statement. MySQL excludes some
// DDL from COM_STMT_PREPARE; only zero-parameter statements may use COM_QUERY.
// CLIENT_MULTI_STATEMENTS remains disabled, including for compound routines.
func textFallback(e error, parameters int) bool {
	var remote *mysql.MySQLError
	return parameters == 0 && errors.As(e, &remote) && remote.Number == 1295
}
