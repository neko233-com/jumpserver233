// Package sqlserverclient uses Microsoft's native TDS driver with pinned routing.
package sqlserverclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/golang-sql/sqlexp"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

type Target = sqlclient.Target
type Credentials = sqlclient.Credentials
type Input = sqlclient.Input
type Result = sqlclient.Result

const maxWireBytes = 4 * sqlclient.MaxResultBytes

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
		c.Conn.Close()
		return 0, sqlclient.ErrResultLimit
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, e := c.Conn.Read(p)
	c.budget.remaining.Add(-int64(n))
	return n, e
}

type tunnelDialer struct {
	target Target
	budget *wireBudget
}

func (d tunnelDialer) HostName() string { return d.target.Host }
func (d tunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != net.JoinHostPort(d.target.Host, strconv.Itoa(d.target.Port)) {
		return nil, sqlclient.ErrDenied
	}
	c, e := sshclient.DialTunnel(ctx, d.target.Gateways, address, 5*time.Second)
	if e != nil {
		return nil, e
	}
	return &budgetConnection{Conn: c, budget: d.budget}, nil
}
func config(t Target, c Credentials) (msdsn.Config, error) {
	if sqlclient.ValidateSettings(t.Settings) != nil || t.Host == "" || strings.ContainsAny(t.Host, "\\/\x00\r\n") || t.Username == "" || t.Port < 1 || t.Port > 65535 || c.Password == "" {
		return msdsn.Config{}, sqlclient.ErrInvalid
	}
	p := msdsn.Config{Host: t.Host, Port: uint64(t.Port), Database: t.Database, User: t.Username, Password: c.Password, AppName: "jumpserver233", DisableRetry: true, DialTimeout: 5 * time.Second, PacketSize: 4096, Protocols: []string{"tcp"}, Encryption: msdsn.EncryptionDisabled, HostInCertificateProvided: true}
	if t.TLSMode == "verify-full" {
		name := t.ServerName
		if name == "" {
			name = t.Host
		}
		p.Encryption = msdsn.EncryptionRequired
		p.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
		if t.RootCAPEM != "" {
			pool, e := x509.SystemCertPool()
			if e != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
				return msdsn.Config{}, sqlclient.ErrInvalid
			}
			p.TLSConfig.RootCAs = pool
		}
	}
	return p, nil
}
func open(ctx context.Context, t Target, c Credentials, b *wireBudget) (*sql.DB, *sql.Conn, error) {
	p, e := config(t, c)
	if e != nil {
		return nil, nil, e
	}
	b.remaining.Store(maxWireBytes)
	connector := mssql.NewConnectorConfig(p)
	connector.Dialer = tunnelDialer{t, b}
	connector.SessionInitSQL = "SET QUOTED_IDENTIFIER ON; SET ANSI_NULLS ON; SET XACT_ABORT ON; SET IMPLICIT_TRANSACTIONS OFF; SET NOCOUNT OFF;"
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
func Ping(ctx context.Context, t Target, c Credentials) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	db, conn, e := open(ctx, t, c, &wireBudget{})
	if e != nil {
		return e
	}
	defer db.Close()
	defer conn.Close()
	if conn.PingContext(ctx) != nil {
		return sqlclient.ErrUnavailable
	}
	return nil
}
func bind(input []json.RawMessage) ([]any, error) {
	args := make([]any, len(input))
	for i, p := range input {
		var v any
		dec := json.NewDecoder(strings.NewReader(string(p)))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			return nil, sqlclient.ErrInvalid
		}
		switch value := v.(type) {
		case json.Number:
			v = string(value)
		case map[string]any, []any:
			v = string(p)
		}
		args[i] = sql.Named("p"+strconv.Itoa(i+1), v)
	}
	return args, nil
}
func Execute(parent context.Context, t Target, c Credentials, in Input, authorize func() error) (out Result, returned error) {
	start := time.Now()
	out = Result{Columns: []sqlclient.Column{}, Rows: [][]*string{}, Transaction: "not_started", ReadOnly: t.ReadOnly || in.ReadOnly}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()
	in.Dialect = "sqlserver"
	if sqlclient.ValidateInput(in) != nil {
		return out, sqlclient.ErrInvalid
	}
	redacted, _ := sqlclient.AuditSQLServer(in.SQL)
	if out.ReadOnly && !sqlclient.ReadOnlySQLServer(redacted) {
		out.ErrorCode = "read_only"
		return out, sqlclient.ErrDenied
	}
	args, e := bind(in.Parameters)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	b := &wireBudget{}
	db, conn, e := open(ctx, t, c, b)
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
		tx, e = conn.BeginTx(ctx, nil)
		if e != nil {
			out.ErrorCode = "connection_failed"
			return out, sqlclient.ErrUnavailable
		}
		defer tx.Rollback()
		out.Transaction = "rolled_back"
	}
	if authorize != nil && authorize() != nil {
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	if !out.ReadOnly {
		out.Transaction = "unknown"
	}
	messages := &sqlexp.ReturnMessage{}
	args = append(args, messages)
	var rows *sql.Rows
	if tx != nil {
		rows, e = tx.QueryContext(ctx, in.SQL, args...)
	} else {
		rows, e = conn.QueryContext(ctx, in.SQL, args...)
	}
	if e != nil {
		return queryError(out, e, ctx, b)
	}
	defer func() { cancel(); _ = rows.Close() }()
	total, cells, rowCount, sets := 0, 0, 0, 0
	counts := false
	active := true
	for active {
		switch message := messages.Message(ctx).(type) {
		case sqlexp.MsgError:
			return queryError(out, message.Error, ctx, b)
		case sqlexp.MsgRowsAffected:
			out.AffectedRows += message.Count
			counts = true
		case sqlexp.MsgNext:
			columns, e := rows.ColumnTypes()
			if e != nil {
				return queryError(out, e, ctx, b)
			}
			if len(columns) == 0 {
				continue
			}
			sets++
			if sets > 16 {
				out.ErrorCode = "result_limit"
				out.Truncated = true
				return out, sqlclient.ErrResultLimit
			}
			set := sqlclient.ResultSet{Columns: []sqlclient.Column{}, Rows: [][]*string{}}
			for _, column := range columns {
				set.Columns = append(set.Columns, sqlclient.Column{Name: column.Name(), DatabaseType: column.DatabaseTypeName()})
			}
			for rows.Next() {
				if rowCount >= in.RowLimit || cells+len(columns) > sqlclient.MaxResultCells {
					out.ErrorCode = "result_limit"
					out.Truncated = true
					return out, sqlclient.ErrResultLimit
				}
				rowCount++
				cells += len(columns)
				raw := make([]any, len(columns))
				dest := make([]any, len(columns))
				for i := range raw {
					dest[i] = &raw[i]
				}
				if e = rows.Scan(dest...); e != nil {
					return queryError(out, e, ctx, b)
				}
				row := make([]*string, len(raw))
				for i, v := range raw {
					if v == nil {
						continue
					}
					value := cell(v, columns[i].DatabaseTypeName())
					if len(value) > sqlclient.MaxCellBytes {
						out.Truncated = true
						value = value[:sqlclient.MaxCellBytes]
						for !utf8.ValidString(value) {
							value = value[:len(value)-1]
						}
					}
					total += len(value)
					if total > sqlclient.MaxResultBytes {
						out.ErrorCode = "result_limit"
						out.Truncated = true
						return out, sqlclient.ErrResultLimit
					}
					row[i] = &value
				}
				set.Rows = append(set.Rows, row)
			}
			if e = rows.Err(); e != nil {
				return queryError(out, e, ctx, b)
			}
			if sets == 1 {
				out.Columns = set.Columns
				out.Rows = set.Rows
			} else {
				out.ResultSets = append(out.ResultSets, set)
			}
		case sqlexp.MsgNextResultSet:
			active = rows.NextResultSet()
		}
		if ctx.Err() != nil {
			return queryError(out, ctx.Err(), ctx, b)
		}
	}
	if e = rows.Err(); e != nil {
		return queryError(out, e, ctx, b)
	}
	if e = rows.Close(); e != nil {
		return queryError(out, e, ctx, b)
	}
	if authorize != nil && authorize() != nil {
		out.Rows = nil
		out.ResultSets = nil
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	if tx != nil {
		if e = tx.Rollback(); e != nil {
			out.ErrorCode = "query_failed"
			return out, errors.New("database rollback failed")
		}
	} else {
		out.Transaction = "server_managed"
	}
	if out.ReadOnly {
		out.AffectedRows = int64(rowCount)
	} else {
		out.AffectedRowsKnown = &counts
	}
	return out, nil
}
func cell(v any, kind string) string {
	switch x := v.(type) {
	case []byte:
		switch strings.ToUpper(kind) {
		case "BINARY", "VARBINARY", "IMAGE", "TIMESTAMP", "ROWVERSION":
			return "0x" + hex.EncodeToString(x)
		}
		if utf8.Valid(x) {
			return string(x)
		}
		return "0x" + hex.EncodeToString(x)
	case time.Time:
		return x.Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(x)
	}
}
func queryError(out Result, e error, ctx context.Context, b *wireBudget) (Result, error) {
	out.ErrorCode = "query_failed"
	if b.exceeded.Load() || errors.Is(e, mssql.ErrReadLimit) {
		out.Truncated = true
		out.ErrorCode = "result_limit"
		return out, sqlclient.ErrResultLimit
	}
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	return out, errors.New("database query failed")
}
