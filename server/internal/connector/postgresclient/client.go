package postgresclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

const (
	MaxRows           = sqlclient.MaxRows
	MaxResultBytes    = sqlclient.MaxResultBytes
	MaxCellBytes      = sqlclient.MaxCellBytes
	MaxSQLBytes       = sqlclient.MaxSQLBytes
	MaxParameterBytes = sqlclient.MaxParameterBytes
	MaxResultCells    = sqlclient.MaxResultCells
)

var (
	ErrInvalid     = sqlclient.ErrInvalid
	ErrUnavailable = sqlclient.ErrUnavailable
	ErrDenied      = sqlclient.ErrDenied
	ErrResultLimit = sqlclient.ErrResultLimit
)

type Settings = sqlclient.Settings
type Target = sqlclient.Target
type Credentials = sqlclient.Credentials
type Input = sqlclient.Input
type Column = sqlclient.Column
type Result = sqlclient.Result

func ValidateSettings(s Settings) error { return sqlclient.ValidateSettings(s) }
func parameters(input []json.RawMessage) ([][]byte, error) {
	if len(input) > 100 {
		return nil, ErrInvalid
	}
	out := make([][]byte, len(input))
	size := 0
	for i, p := range input {
		p = bytes.TrimSpace(p)
		if !json.Valid(p) || len(p) > 65536 {
			return nil, ErrInvalid
		}
		if string(p) == "null" {
			continue
		}
		var value string
		if len(p) > 0 && p[0] == '"' {
			if json.Unmarshal(p, &value) != nil {
				return nil, ErrInvalid
			}
			if strings.ContainsRune(value, 0) {
				return nil, ErrInvalid
			}
			out[i] = []byte(value)
		} else {
			out[i] = append([]byte(nil), p...)
		}
		size += len(out[i])
		if size > MaxParameterBytes {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func ValidateInput(in Input) error {
	if strings.TrimSpace(in.SQL) == "" || len(in.SQL) > MaxSQLBytes || !utf8.ValidString(in.SQL) || strings.ContainsRune(in.SQL, 0) || in.RowLimit < 1 || in.RowLimit > MaxRows || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 {
		return ErrInvalid
	}
	if _, e := AuditSQL(in.SQL); e != nil {
		return e
	}
	_, e := parameters(in.Parameters)
	return e
}
func connectionConfig(target Target, secret Credentials) (*pgconn.Config, error) {
	if ValidateSettings(target.Settings) != nil || target.Host == "" || target.Port < 1 || target.Port > 65535 || target.Username == "" || secret.Password == "" {
		return nil, ErrInvalid
	}
	// Never parse caller-provided DSNs or inherit service/password/certificate
	// files. All transport and authentication fields are assigned explicitly.
	c, e := isolatedBaseConfig()
	if e != nil {
		return nil, ErrInvalid
	}
	c.Host = target.Host
	c.Port = uint16(target.Port)
	c.Database = target.Database
	c.User = target.Username
	c.Password = secret.Password
	c.Fallbacks = nil
	c.RuntimeParams = map[string]string{"application_name": "jumpserver233", "standard_conforming_strings": "on", "client_encoding": "UTF8"}
	c.ConnectTimeout = 5 * time.Second
	c.MaxProtocolMessageBodyLen = MaxResultBytes
	c.KerberosSrvName = ""
	c.KerberosSpn = ""
	c.OAuthTokenProvider = nil
	c.OnNotice = nil
	c.OnNotification = nil
	c.ValidateConnect = nil
	c.AfterConnect = nil
	c.TLSConfig = nil
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
				return nil, ErrInvalid
			}
			tc.RootCAs = pool
		}
		c.TLSConfig = tc
	}
	if len(target.Gateways) > 0 {
		c.LookupFunc = func(context.Context, string) ([]string, error) { return []string{target.Host}, nil }
		c.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return sshclient.DialTunnel(ctx, target.Gateways, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), 5*time.Second)
		}
	} else {
		c.LookupFunc = net.DefaultResolver.LookupHost
		c.DialFunc = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return c, nil
}
func Ping(ctx context.Context, target Target, credentials Credentials) error {
	cfg, e := connectionConfig(target, credentials)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, e := pgconn.ConnectConfig(ctx, cfg)
	if e != nil {
		return ErrUnavailable
	}
	defer closeConnection(c)
	if _, e = c.Exec(ctx, "SELECT 1").ReadAll(); e != nil {
		return ErrUnavailable
	}
	return nil
}
func Execute(ctx context.Context, target Target, credentials Credentials, in Input, beforeCommit func() error) (out Result, returned error) {
	started := time.Now()
	out = Result{Columns: []Column{}, Rows: [][]*string{}, ReadOnly: target.ReadOnly || in.ReadOnly, Transaction: "not_started"}
	defer func() { out.DurationMS = time.Since(started).Milliseconds() }()
	if ValidateInput(in) != nil {
		return out, ErrInvalid
	}
	values, e := parameters(in.Parameters)
	if e != nil {
		return out, e
	}
	cfg, e := connectionConfig(target, credentials)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	cfg.RuntimeParams["statement_timeout"] = strconv.Itoa(in.TimeoutSeconds * 1000)
	cfg.RuntimeParams["lock_timeout"] = strconv.Itoa(in.TimeoutSeconds * 1000)
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = strconv.Itoa(in.TimeoutSeconds * 1000)
	c, e := pgconn.ConnectConfig(ctx, cfg)
	if e != nil {
		if ctx.Err() != nil {
			out.ErrorCode = "cancelled"
			return out, ctx.Err()
		}
		out.ErrorCode = "connection_failed"
		return out, ErrUnavailable
	}
	defer closeConnection(c)
	begin := "BEGIN"
	if out.ReadOnly {
		begin = "BEGIN READ ONLY"
	}
	if _, e = c.Exec(ctx, begin).ReadAll(); e != nil {
		if ctx.Err() != nil {
			out.ErrorCode = "cancelled"
			return out, ctx.Err()
		}
		out.ErrorCode = "connection_failed"
		return out, ErrUnavailable
	}
	out.Transaction = "rolled_back"
	defer func() {
		if out.Transaction != "committed" {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_, _ = c.Exec(cleanup, "ROLLBACK").ReadAll()
		}
	}()
	reader := c.ExecParams(ctx, in.SQL, values, nil, nil, nil)
	total, cells := 0, 0
	for reader.NextRow() {
		if len(out.Columns) == 0 {
			for _, f := range reader.FieldDescriptions() {
				out.Columns = append(out.Columns, Column{Name: f.Name, TypeOID: f.DataTypeOID})
			}
		}
		if len(out.Rows) >= in.RowLimit {
			out.Truncated = true
			out.ErrorCode = "result_limit"
			cancel()
			closeConnection(c)
			return out, ErrResultLimit
		}
		cells += len(reader.Values())
		if cells > MaxResultCells {
			out.Truncated = true
			out.ErrorCode = "result_limit"
			cancel()
			closeConnection(c)
			return out, ErrResultLimit
		}
		row := make([]*string, len(reader.Values()))
		for i, v := range reader.Values() {
			if v == nil {
				continue
			}
			if len(v) > MaxCellBytes {
				out.Truncated = true
				v = v[:MaxCellBytes]
				for !utf8.Valid(v) && len(v) > 0 {
					v = v[:len(v)-1]
				}
			}
			total += len(v)
			if total > MaxResultBytes {
				out.Truncated = true
				out.ErrorCode = "result_limit"
				cancel()
				closeConnection(c)
				return out, ErrResultLimit
			}
			value := string(v)
			row[i] = &value
		}
		out.Rows = append(out.Rows, row)
	}
	if len(out.Columns) == 0 {
		for _, f := range reader.FieldDescriptions() {
			out.Columns = append(out.Columns, Column{Name: f.Name, TypeOID: f.DataTypeOID})
		}
	}
	tag, e := reader.Close()
	if e != nil {
		out.ErrorCode = "query_failed"
		var pg *pgconn.PgError
		if errors.As(e, &pg) {
			out.SQLState = pg.Code
			out.ErrorPosition = pg.Position
		}
		if ctx.Err() != nil {
			out.ErrorCode = "cancelled"
			return out, ctx.Err()
		}
		return out, errors.New("database query failed")
	}
	out.CommandTag = tag.String()
	out.AffectedRows = tag.RowsAffected()
	if beforeCommit != nil {
		if e = beforeCommit(); e != nil {
			out.ErrorCode = "access_revoked"
			return out, ErrDenied
		}
	}
	if out.ReadOnly {
		return out, nil
	}
	if _, e = c.Exec(ctx, "COMMIT").ReadAll(); e != nil {
		out.Transaction = "unknown"
		out.ErrorCode = "commit_unknown"
		return out, errors.New("database commit result unknown")
	}
	out.Transaction = "committed"
	return out, nil
}
func closeConnection(c *pgconn.PgConn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// pgconn treats even service=” as a service-file request. Use a private,
// credential-free bootstrap file so ambient PGSERVICE/PGSERVICEFILE cannot
// read a caller-selected file; never mutate process environment variables.
func isolatedBaseConfig() (*pgconn.Config, error) {
	f, e := os.CreateTemp("", ".jms233-pg-bootstrap-*")
	if e != nil {
		return nil, ErrUnavailable
	}
	defer os.Remove(f.Name())
	_, e = f.WriteString("[jms233]\n")
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return nil, ErrUnavailable
	}
	filename := strings.ReplaceAll(strings.ReplaceAll(f.Name(), "\\", "\\\\"), "'", "\\'")
	return pgconn.ParseConfig("host=127.0.0.1 port=5432 dbname=postgres user=jms233 password=unused sslmode=disable sslrootcert='' sslcert='' sslkey='' sslpassword='' options='' service=jms233 servicefile='" + filename + "' passfile='' target_session_attrs=any connect_timeout=5 channel_binding=prefer require_auth=password,md5,scram-sha-256 sslnegotiation=postgres min_protocol_version=3.0 max_protocol_version=3.0")
}
