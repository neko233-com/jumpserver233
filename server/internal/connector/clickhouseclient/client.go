// Package clickhouseclient implements the official HTTPS SQL interface without
// exposing credentials or putting SQL/parameters in request URLs.
package clickhouseclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

type Target = sqlclient.Target
type Credentials = sqlclient.Credentials
type Input = sqlclient.Input
type Result = sqlclient.Result

const maxWireBytes = 4 * sqlclient.MaxResultBytes

type remoteError struct{ code string }

func (e remoteError) Error() string { return "ClickHouse query failed" }

func client(t Target, c Credentials) (*http.Client, *http.Transport, error) {
	if sqlclient.ValidateSettings(t.Settings) != nil || t.Host == "" || t.Port < 1 || t.Port > 65535 || t.Username == "" || strings.ContainsAny(t.Username, ":\x00\r\n") || c.Password == "" {
		return nil, nil, sqlclient.ErrInvalid
	}
	name := t.ServerName
	if name == "" {
		name = t.Host
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if t.RootCAPEM != "" {
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
			return nil, nil, sqlclient.ErrInvalid
		}
		tc.RootCAs = roots
	}
	expected := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 65536, TLSHandshakeTimeout: 5 * time.Second, MaxConnsPerHost: 2, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != expected {
			return nil, sqlclient.ErrDenied
		}
		return sshclient.DialTunnel(ctx, t.Gateways, address, 5*time.Second)
	}}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport, nil
}
func request(ctx context.Context, cl *http.Client, t Target, c Credentials, sql string, parameters map[string]string, ro bool, id string, seconds int) ([]byte, http.Header, error) {
	settings := url.Values{"database": {t.Database}, "default_format": {"JSONCompactEachRowWithNamesAndTypes"}, "query_id": {id}, "wait_end_of_query": {"1"}, "buffer_size": {strconv.Itoa(maxWireBytes)}, "max_result_rows": {strconv.Itoa(sqlclient.MaxRows + 1)}, "max_result_bytes": {strconv.Itoa(maxWireBytes)}, "result_overflow_mode": {"throw"}, "max_execution_time": {strconv.Itoa(seconds)}, "send_progress_in_http_headers": {"0"}, "enable_http_compression": {"0"}, "output_format_json_validate_utf8": {"0"}, "output_format_json_quote_denormals": {"1"}, "extremes": {"0"}, "http_write_exception_in_output_format": {"0"}}
	if ro {
		settings.Set("readonly", "1")
		settings.Set("allow_ddl", "0")
	}
	scheme := "https"
	if t.TLSMode == "disable" {
		scheme = "http"
	}
	endpoint := url.URL{Scheme: scheme, Host: net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), Path: "/", RawQuery: settings.Encode()}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	_ = form.WriteField("query", sql)
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_ = form.WriteField(key, parameters[key])
	}
	_ = form.Close()
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &body)
	if e != nil {
		return nil, nil, sqlclient.ErrInvalid
	}
	r.SetBasicAuth(t.Username, c.Password)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r.Header.Set("Accept-Encoding", "identity")
	response, e := cl.Do(r)
	if e != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, sqlclient.ErrUnavailable
	}
	defer response.Body.Close()
	code := response.Header.Get("X-ClickHouse-Exception-Code")
	if code != "" && code != "0" {
		n, e := strconv.ParseUint(code, 10, 32)
		if e != nil {
			return nil, response.Header, sqlclient.ErrUnavailable
		}
		return nil, response.Header, remoteError{strconv.FormatUint(n, 10)}
	}
	if response.StatusCode != http.StatusOK {
		return nil, response.Header, sqlclient.ErrUnavailable
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, response.Header, sqlclient.ErrUnavailable
	}
	if response.ContentLength > maxWireBytes {
		return nil, response.Header, sqlclient.ErrResultLimit
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, maxWireBytes+1))
	if len(raw) > maxWireBytes {
		return nil, response.Header, sqlclient.ErrResultLimit
	}
	if e != nil {
		if ctx.Err() != nil {
			return nil, response.Header, ctx.Err()
		}
		return nil, response.Header, sqlclient.ErrUnavailable
	}
	return raw, response.Header, nil
}
func queryID() (string, error) {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", e
	}
	return "jms233-" + hex.EncodeToString(raw[:]), nil
}
func kill(cl *http.Client, t Target, c Credentials, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cleanupID, e := queryID()
	if e != nil {
		return
	}
	_, _, _ = request(ctx, cl, t, c, "KILL QUERY WHERE query_id = '"+id+"' SYNC", nil, true, cleanupID, 2)
}
func Ping(ctx context.Context, t Target, c Credentials) error {
	in := Input{SQL: "SELECT 1", ReadOnly: true, RowLimit: 1, TimeoutSeconds: 8}
	_, e := Execute(ctx, t, c, in, nil)
	return e
}
func readStatement(verb string) bool {
	switch verb {
	case "SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXISTS", "EXPLAIN":
		return true
	}
	return false
}

func Execute(parent context.Context, t Target, c Credentials, in Input, authorize func() error) (out Result, returned error) {
	started := time.Now()
	out = Result{Columns: []sqlclient.Column{}, Rows: [][]*string{}, ReadOnly: t.ReadOnly || in.ReadOnly, Transaction: "not_started"}
	defer func() { out.DurationMS = time.Since(started).Milliseconds() }()
	in.Dialect = "clickhouse"
	if sqlclient.ValidateInput(in) != nil {
		return out, sqlclient.ErrInvalid
	}
	statement, e := sqlclient.ScanClickHouse(in.SQL)
	if e != nil {
		return out, e
	}
	if out.ReadOnly && !readStatement(statement.Verb) {
		out.ErrorCode = "read_only"
		return out, sqlclient.ErrDenied
	}
	parameters, e := bind(in.Parameters, statement.Parameters)
	if e != nil {
		return out, e
	}
	cl, transport, e := client(t, c)
	if e != nil {
		return out, e
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	if authorize != nil && authorize() != nil {
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	id, e := queryID()
	if e != nil {
		return out, e
	}
	dispatched := true
	defer func() {
		if dispatched && (ctx.Err() != nil || errors.Is(returned, sqlclient.ErrResultLimit)) {
			kill(cl, t, c, id)
		}
	}()
	if !out.ReadOnly {
		out.Transaction = "unknown"
	}
	raw, headers, e := request(ctx, cl, t, c, in.SQL, parameters, out.ReadOnly, id, in.TimeoutSeconds)
	if e != nil {
		return queryError(out, e, ctx)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if out.ReadOnly {
			return queryError(out, sqlclient.ErrUnavailable, ctx)
		}
	} else {
		var frame struct {
			Meta []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"meta"`
			Data [][]json.RawMessage `json:"data"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		var names, types []string
		if decoder.Decode(&names) != nil || decoder.Decode(&types) != nil || len(names) == 0 || len(names) != len(types) {
			return queryError(out, sqlclient.ErrUnavailable, ctx)
		}
		for i, name := range names {
			frame.Meta = append(frame.Meta, struct {
				Name string `json:"name"`
				Type string `json:"type"`
			}{name, types[i]})
		}
		for {
			var record []json.RawMessage
			e := decoder.Decode(&record)
			if e == io.EOF {
				break
			}
			if e != nil {
				return queryError(out, sqlclient.ErrUnavailable, ctx)
			}
			frame.Data = append(frame.Data, record)
			if len(frame.Data) > in.RowLimit {
				out.Truncated = true
				out.ErrorCode = "result_limit"
				return out, sqlclient.ErrResultLimit
			}
		}
		if len(frame.Data) > in.RowLimit || len(frame.Meta) > sqlclient.MaxResultCells {
			out.Truncated = true
			out.ErrorCode = "result_limit"
			return out, sqlclient.ErrResultLimit
		}
		total, cells := 0, 0
		for _, column := range frame.Meta {
			total += len(column.Name) + len(column.Type)
			if total > sqlclient.MaxResultBytes || len(column.Name) > sqlclient.MaxCellBytes || len(column.Type) > sqlclient.MaxCellBytes {
				out.Truncated = true
				out.ErrorCode = "result_limit"
				return out, sqlclient.ErrResultLimit
			}
			out.Columns = append(out.Columns, sqlclient.Column{Name: column.Name, DatabaseType: column.Type})
		}
		for _, record := range frame.Data {
			if len(record) != len(frame.Meta) {
				return queryError(out, sqlclient.ErrUnavailable, ctx)
			}
			cells += len(record)
			if cells > sqlclient.MaxResultCells {
				out.Truncated = true
				out.ErrorCode = "result_limit"
				return out, sqlclient.ErrResultLimit
			}
			row := make([]*string, len(record))
			for i, rawCell := range record {
				if bytes.Equal(rawCell, []byte("null")) {
					continue
				}
				value, e := cell(rawCell)
				if e != nil {
					return queryError(out, e, ctx)
				}
				if len(value) > sqlclient.MaxCellBytes {
					value = value[:sqlclient.MaxCellBytes]
					out.Truncated = true
					for !utf8.ValidString(value) {
						value = value[:len(value)-1]
					}
				}
				total += len(value)
				if total > sqlclient.MaxResultBytes {
					out.Truncated = true
					out.ErrorCode = "result_limit"
					return out, sqlclient.ErrResultLimit
				}
				row[i] = &value
			}
			out.Rows = append(out.Rows, row)
		}
	}
	if authorize != nil && authorize() != nil {
		out.Rows = nil
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	if out.ReadOnly {
		out.Transaction = "read_only"
		out.AffectedRows = int64(len(out.Rows))
	} else {
		out.Transaction = "server_managed"
		known := false
		var summary struct {
			Written string `json:"written_rows"`
		}
		if json.Unmarshal([]byte(headers.Get("X-ClickHouse-Summary")), &summary) == nil {
			if n, e := strconv.ParseInt(summary.Written, 10, 64); e == nil && n >= 0 {
				out.AffectedRows = n
				known = true
			}
		}
		out.AffectedRowsKnown = &known
	}
	dispatched = false
	return out, nil
}
func queryError(out Result, e error, ctx context.Context) (Result, error) {
	out.ErrorCode = "query_failed"
	if errors.Is(e, sqlclient.ErrResultLimit) {
		out.Truncated = true
		out.ErrorCode = "result_limit"
		return out, e
	}
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	var remote remoteError
	if errors.As(e, &remote) {
		out.DatabaseCode = remote.code
		switch remote.code {
		case "164", "242", "472":
			out.ErrorCode = "read_only"
			return out, sqlclient.ErrDenied
		case "158", "307", "396":
			out.ErrorCode = "result_limit"
			out.Truncated = true
			return out, sqlclient.ErrResultLimit
		case "159", "394":
			out.ErrorCode = "cancelled"
			return out, context.DeadlineExceeded
		}
	}
	return out, errors.New("database query failed")
}

// JSON RawMessage preserves invalid UTF-8 bytes from ClickHouse String values.
// Decode escapes before deciding whether a value requires hexadecimal display.
func cell(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", sqlclient.ErrInvalid
	}
	if raw[0] != '"' {
		if !utf8.Valid(raw) {
			return "0x" + hex.EncodeToString(raw), nil
		}
		return string(raw), nil
	}
	value := make([]byte, 0, len(raw))
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			value = append(value, raw[i])
			continue
		}
		i++
		if i >= len(raw)-1 {
			return "", sqlclient.ErrInvalid
		}
		switch raw[i] {
		case '"', '\\', '/':
			value = append(value, raw[i])
		case 'b':
			value = append(value, '\b')
		case 'f':
			value = append(value, '\f')
		case 'n':
			value = append(value, '\n')
		case 'r':
			value = append(value, '\r')
		case 't':
			value = append(value, '\t')
		case 'u':
			if i+4 >= len(raw) {
				return "", sqlclient.ErrInvalid
			}
			n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if e != nil {
				return "", e
			}
			i += 4
			r := rune(n)
			if utf16.IsSurrogate(r) {
				if r >= 0xD800 && r <= 0xDBFF && i+6 < len(raw)-1 && raw[i+1] == '\\' && raw[i+2] == 'u' {
					low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
					if e == nil && low >= 0xDC00 && low <= 0xDFFF {
						r = utf16.DecodeRune(r, rune(low))
						i += 6
					} else {
						r = utf8.RuneError
					}
				} else {
					r = utf8.RuneError
				}
			}
			value = utf8.AppendRune(value, r)
		default:
			return "", sqlclient.ErrInvalid
		}
	}
	if !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return "0x" + hex.EncodeToString(value), nil
	}
	return string(value), nil
}
