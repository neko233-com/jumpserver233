// Package redisclient implements bounded RESP2 database requests using the
// platform vault, one disposable authenticated connection and pinned gateways.
package redisclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/databasewire"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Target = sqlclient.Target
type Credentials = sqlclient.Credentials
type Input = sqlclient.Input
type Result = sqlclient.Result

const MaxWireBytes = 4 * sqlclient.MaxResultBytes

var blocked = wordSet("AUTH HELLO SELECT RESET QUIT MULTI EXEC DISCARD WATCH UNWATCH SUBSCRIBE PSUBSCRIBE SSUBSCRIBE UNSUBSCRIBE PUNSUBSCRIBE SUNSUBSCRIBE MONITOR SYNC PSYNC REPLICAOF SLAVEOF MIGRATE RESTORE-ASKING CLUSTER CONFIG ACL MODULE SHUTDOWN DEBUG CLIENT SCRIPT FUNCTION")
var reads = wordSet("PING ECHO GET MGET STRLEN GETRANGE EXISTS TYPE TTL PTTL DUMP LLEN LRANGE LINDEX LPOS SCARD SMEMBERS SISMEMBER SMISMEMBER SRANDMEMBER SSCAN SDIFF SINTER SUNION HGET HGETALL HKEYS HLEN HMGET HRANDFIELD HEXISTS HSTRLEN HVALS HSCAN ZCARD ZCOUNT ZLEXCOUNT ZRANGE ZRANGEBYSCORE ZREVRANGE ZREVRANGEBYSCORE ZRANK ZREVRANK ZSCORE ZMSCORE ZSCAN ZDIFF ZINTER ZUNION XINFO XREAD XLEN XRANGE XREVRANGE XPENDING SCAN KEYS DBSIZE TIME INFO COMMAND BITCOUNT BITPOS GEOHASH GEOPOS GEODIST GEOSEARCH GEORADIUS_RO GEORADIUSBYMEMBER_RO PFCOUNT SORT_RO TOUCH")
var codes = wordSet("ERR WRONGTYPE NOPERM NOAUTH WRONGPASS BUSY NOSCRIPT OOM MISCONF READONLY MASTERDOWN CLUSTERDOWN CROSSSLOT MOVED ASK LOADING EXECABORT TRYAGAIN BUSYKEY UNBLOCKED")

func wordSet(value string) map[string]bool {
	m := map[string]bool{}
	for _, word := range strings.Fields(value) {
		m[word] = true
	}
	return m
}
func ReadCommand(args [][]byte) bool {
	cmd := string(args[0])
	if reads[cmd] {
		return true
	}
	if len(args) > 1 {
		second := strings.ToUpper(string(args[1]))
		return cmd == "MEMORY" && (second == "USAGE" || second == "STATS" || second == "DOCTOR" || second == "HELP") || cmd == "OBJECT" && (second == "ENCODING" || second == "FREQ" || second == "IDLETIME" || second == "REFCOUNT" || second == "HELP")
	}
	return false
}

type remoteError struct{ code string }

func (e remoteError) Error() string { return "Redis command failed" }

type node struct {
	kind  byte
	text  []byte
	items []node
	null  bool
}
type reader struct {
	reader *bufio.Reader
	nodes  int
}

func (r *reader) line() ([]byte, error) {
	line, e := r.reader.ReadSlice('\n')
	if errors.Is(e, bufio.ErrBufferFull) {
		return nil, sqlclient.ErrResultLimit
	}
	if e != nil {
		return nil, e
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, sqlclient.ErrUnavailable
	}
	return line[:len(line)-2], nil
}
func (r *reader) value(depth int) (node, error) {
	r.nodes++
	if depth > 32 || r.nodes > sqlclient.MaxResultCells {
		return node{}, sqlclient.ErrResultLimit
	}
	kind, e := r.reader.ReadByte()
	if e != nil {
		return node{}, e
	}
	line, e := r.line()
	if e != nil {
		return node{}, e
	}
	out := node{kind: kind}
	switch kind {
	case '+':
		out.text = bytes.Clone(line)
	case '-':
		code := strings.SplitN(string(line), " ", 2)[0]
		if !codes[code] {
			code = "ERR"
		}
		return out, remoteError{code}
	case ':':
		if _, e := strconv.ParseInt(string(line), 10, 64); e != nil {
			return out, sqlclient.ErrUnavailable
		}
		out.text = bytes.Clone(line)
	case '$', '*':
		n, e := strconv.ParseInt(string(line), 10, 64)
		if e != nil || n < -1 {
			return out, sqlclient.ErrUnavailable
		}
		if n == -1 {
			out.null = true
			return out, nil
		}
		if kind == '$' {
			if n > MaxWireBytes-2 {
				return out, sqlclient.ErrResultLimit
			}
			data := make([]byte, int(n)+2)
			if _, e = io.ReadFull(r.reader, data); e != nil {
				return out, e
			}
			if data[len(data)-2] != '\r' || data[len(data)-1] != '\n' {
				return out, sqlclient.ErrUnavailable
			}
			out.text = data[:len(data)-2]
		} else {
			if n > int64(sqlclient.MaxResultCells-r.nodes) {
				return out, sqlclient.ErrResultLimit
			}
			out.items = make([]node, int(n))
			for i := range out.items {
				out.items[i], e = r.value(depth + 1)
				if e != nil {
					return out, e
				}
			}
		}
	default:
		return out, sqlclient.ErrUnavailable
	}
	return out, nil
}

type limitedConnection struct {
	net.Conn
	remaining int
}

func (c *limitedConnection) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, sqlclient.ErrResultLimit
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, e := c.Conn.Read(p)
	c.remaining -= n
	return n, e
}
func write(conn net.Conn, args [][]byte) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n", len(arg))
		b.Write(arg)
		b.WriteString("\r\n")
	}
	for b.Len() > 0 {
		n, e := conn.Write(b.Bytes())
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		b.Next(n)
	}
	return nil
}
func round(conn net.Conn, r *reader, args ...string) (node, error) {
	raw := make([][]byte, len(args))
	for i, s := range args {
		raw[i] = []byte(s)
	}
	if e := write(conn, raw); e != nil {
		return node{}, e
	}
	return r.value(0)
}
func value(n node) any {
	if n.null {
		return nil
	}
	if n.kind == '*' {
		a := make([]any, len(n.items))
		for i, v := range n.items {
			a[i] = value(v)
		}
		return a
	}
	if n.kind == ':' {
		return json.Number(n.text)
	}
	if !utf8.Valid(n.text) || bytes.IndexByte(n.text, 0) >= 0 {
		return map[string]string{"$binary": hex.EncodeToString(n.text)}
	}
	return string(n.text)
}
func display(n node) (string, string, error) {
	if n.null {
		return "null", "", nil
	}
	switch n.kind {
	case '*':
		b, e := json.Marshal(value(n))
		return "array", string(b), e
	case ':':
		return "integer", string(n.text), nil
	case '+':
		return "status", string(n.text), nil
	default:
		if !utf8.Valid(n.text) || bytes.IndexByte(n.text, 0) >= 0 {
			return "binary", "0x" + hex.EncodeToString(n.text), nil
		}
		return "string", string(n.text), nil
	}
}
func failure(out Result, e error, ctx context.Context) (Result, error) {
	out.ErrorCode = "query_failed"
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && ctx.Err() == nil {
		out.ErrorCode = "cancelled"
		return out, context.DeadlineExceeded
	}
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	if errors.Is(e, sqlclient.ErrResultLimit) {
		out.Truncated = true
		out.ErrorCode = "result_limit"
		return out, e
	}
	var remote remoteError
	if errors.As(e, &remote) {
		out.DatabaseCode = remote.code
	}
	return out, errors.New("database command failed")
}
func ValidateSettings(s sqlclient.Settings) error {
	if sqlclient.ValidateSettings(s) != nil || s.AuthDatabase != "" {
		return sqlclient.ErrInvalid
	}
	n, e := strconv.Atoi(s.Database)
	if e != nil || n < 0 || n > 2147483647 || strconv.Itoa(n) != s.Database {
		return sqlclient.ErrInvalid
	}
	return nil
}
func Ping(ctx context.Context, t Target, c Credentials) error {
	_, e := Execute(ctx, t, c, Input{SQL: `["PING"]`, ReadOnly: true, RowLimit: 1, TimeoutSeconds: 8}, nil)
	return e
}
func Execute(parent context.Context, t Target, c Credentials, in Input, authorize func() error) (out Result, returned error) {
	start := time.Now()
	out = Result{Columns: []sqlclient.Column{}, Rows: [][]*string{}, ReadOnly: t.ReadOnly || in.ReadOnly, Transaction: "not_started"}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()
	in.Dialect = "redis"
	if sqlclient.ValidateInput(in) != nil {
		return out, sqlclient.ErrInvalid
	}
	args, e := sqlclient.RedisCommand(in.SQL)
	if e != nil || blocked[string(args[0])] {
		return out, sqlclient.ErrInvalid
	}
	if out.ReadOnly && !ReadCommand(args) {
		out.ErrorCode = "read_only"
		return out, sqlclient.ErrDenied
	}
	database, e := strconv.Atoi(t.Database)
	if ValidateSettings(t.Settings) != nil || e != nil || database < 0 || database > 2147483647 || t.Username == "" || c.Password == "" {
		return out, sqlclient.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	if authorize != nil && authorize() != nil {
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	conn, e := databasewire.Dial(ctx, t)
	if e != nil {
		return failure(out, e, ctx)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	bounded := &limitedConnection{Conn: conn, remaining: MaxWireBytes}
	r := &reader{reader: bufio.NewReaderSize(bounded, sqlclient.MaxCellBytes+2)}
	if reply, authError := round(conn, r, "AUTH", t.Username, c.Password); authError != nil {
		return failure(out, authError, ctx)
	} else if reply.kind != '+' || string(reply.text) != "OK" {
		return failure(out, sqlclient.ErrUnavailable, ctx)
	}
	if _, e = round(conn, r, "SELECT", strconv.Itoa(database)); e != nil {
		return failure(out, e, ctx)
	}
	if ctx.Err() != nil {
		return failure(out, ctx.Err(), ctx)
	}
	if authorize != nil && authorize() != nil {
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	if !out.ReadOnly {
		out.Transaction = "unknown"
		known := false
		out.AffectedRowsKnown = &known
	}
	if e = write(conn, args); e != nil {
		return failure(out, e, ctx)
	}
	root, e := r.value(0)
	if e != nil {
		return failure(out, e, ctx)
	}
	items := []node{root}
	if root.kind == '*' && !root.null {
		items = root.items
	}
	if len(items) > in.RowLimit {
		out.Truncated = true
		out.ErrorCode = "result_limit"
		return out, sqlclient.ErrResultLimit
	}
	out.Columns = []sqlclient.Column{{Name: "index"}, {Name: "type"}, {Name: "value"}}
	total := 0
	for index, item := range items {
		kind, text, e := display(item)
		if e != nil {
			return failure(out, e, ctx)
		}
		if len(text) > sqlclient.MaxCellBytes {
			text = text[:sqlclient.MaxCellBytes]
			for !utf8.ValidString(text) {
				text = text[:len(text)-1]
			}
			out.Truncated = true
		}
		total += len(text) + len(kind) + 20
		if total > sqlclient.MaxResultBytes {
			out.Truncated = true
			out.ErrorCode = "result_limit"
			return out, sqlclient.ErrResultLimit
		}
		position := strconv.Itoa(index)
		var cell *string
		if !item.null {
			cell = &text
		}
		out.Rows = append(out.Rows, []*string{&position, &kind, cell})
	}
	if authorize != nil && authorize() != nil {
		out.Rows = nil
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	out.AffectedRows = int64(len(out.Rows))
	if out.ReadOnly {
		out.Transaction = "read_only"
	} else {
		out.Transaction = "server_managed"
		known := false
		out.AffectedRowsKnown = &known
	}
	return out, nil
}
