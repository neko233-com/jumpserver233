// Package mongodbclient executes native BSON commands with verified transports,
// fixed destinations and bounded replies. Credentials never leave the server.
package mongodbclient

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

// Non-awaitData getMore does not accept maxTimeMS. Keep cancellation while
// suppressing only the deadline used by the driver to add that server field.
type cursorContext struct{ context.Context }

func (cursorContext) Deadline() (time.Time, bool) { return time.Time{}, false }

type quietLogger struct{}

func (quietLogger) Info(int, string, ...any)    {}
func (quietLogger) Error(error, string, ...any) {}
func ValidateSettings(s sqlclient.Settings) error {
	if sqlclient.ValidateSettings(s) != nil {
		return sqlclient.ErrInvalid
	}
	for _, name := range []string{s.Database, s.AuthDatabase} {
		if name == "" {
			continue
		}
		if len(name) >= 64 || !utf8.ValidString(name) || strings.ContainsAny(name, `/\. "$<>:|?*`) {
			return sqlclient.ErrInvalid
		}
	}
	return nil
}
func client(t Target, c Credentials, budget *wireBudget) (*mongo.Client, error) {
	if ValidateSettings(t.Settings) != nil || t.Host == "" || t.Username == "" || c.Password == "" || t.Port < 1 || t.Port > 65535 {
		return nil, sqlclient.ErrInvalid
	}
	source := t.AuthDatabase
	if source == "" {
		source = t.Database
	}
	return mongo.Connect(options.Client().SetHosts([]string{net.JoinHostPort(t.Host, strconv.Itoa(t.Port))}).SetDirect(true).SetAuth(options.Credential{AuthMechanism: "SCRAM-SHA-256", AuthSource: source, Username: t.Username, Password: c.Password}).SetDialer(&dialer{target: t, budget: budget}).SetCompressors([]string{}).SetRetryReads(false).SetRetryWrites(false).SetMinPoolSize(0).SetMaxPoolSize(1).SetMaxConnecting(1).SetConnectTimeout(5 * time.Second).SetServerSelectionTimeout(5 * time.Second).SetServerMonitoringMode("poll").SetHeartbeatInterval(30 * time.Second).SetLoggerOptions(options.Logger().SetSink(quietLogger{})).SetAppName("jumpserver233"))
}
func failure(out Result, e error, ctx context.Context, budget *wireBudget) (Result, error) {
	out.ErrorCode = "query_failed"
	if ctx.Err() != nil {
		out.ErrorCode = "cancelled"
		return out, ctx.Err()
	}
	if errors.Is(e, sqlclient.ErrResultLimit) || budget.exceeded.Load() {
		out.Truncated = true
		out.ErrorCode = "result_limit"
		return out, sqlclient.ErrResultLimit
	}
	var command mongo.CommandError
	var writes mongo.WriteException
	var bulk mongo.BulkWriteException
	switch {
	case errors.As(e, &command):
		out.DatabaseCode = strconv.FormatInt(int64(command.Code), 10)
	case errors.As(e, &writes):
		if len(writes.WriteErrors) > 0 {
			out.DatabaseCode = strconv.Itoa(writes.WriteErrors[0].Code)
		} else if writes.WriteConcernError != nil {
			out.DatabaseCode = strconv.Itoa(writes.WriteConcernError.Code)
		}
	case errors.As(e, &bulk):
		if len(bulk.WriteErrors) > 0 {
			out.DatabaseCode = strconv.Itoa(bulk.WriteErrors[0].Code)
		} else if bulk.WriteConcernError != nil {
			out.DatabaseCode = strconv.Itoa(bulk.WriteConcernError.Code)
		}
	}
	return out, errors.New("database command failed")
}
func Ping(ctx context.Context, t Target, c Credentials) error {
	_, e := Execute(ctx, t, c, Input{SQL: `{"ping":1}`, ReadOnly: true, RowLimit: 10, TimeoutSeconds: 8}, nil)
	return e
}
func Execute(parent context.Context, t Target, c Credentials, in Input, authorize func() error) (out Result, returned error) {
	start := time.Now()
	out = Result{Columns: []sqlclient.Column{}, Rows: [][]*string{}, ReadOnly: t.ReadOnly || in.ReadOnly, Transaction: "not_started"}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()
	in.Dialect = "mongodb"
	if sqlclient.ValidateInput(in) != nil {
		return out, sqlclient.ErrInvalid
	}
	command, verb, e := prepare(in, t.Database, out.ReadOnly)
	if e != nil {
		if errors.Is(e, sqlclient.ErrDenied) {
			out.ErrorCode = "read_only"
		}
		if errors.Is(e, errScope) {
			out.ErrorCode = "database_scope"
		}
		return out, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	budget := &wireBudget{}
	budget.remaining.Store(MaxWireBytes)
	if authorize != nil && authorize() != nil {
		out.ErrorCode = "access_revoked"
		return out, sqlclient.ErrDenied
	}
	cl, e := client(t, c, budget)
	if e != nil {
		return out, e
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		cl.Disconnect(cleanup)
	}()
	session, e := cl.StartSession()
	if e != nil {
		return failure(out, e, ctx, budget)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		session.EndSession(cleanup)
	}()
	ctx = mongo.NewSessionContext(ctx, session)
	var cursorID int64
	collection := ""
	defer func() {
		if cursorID == 0 || collection == "" {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		cleanup = mongo.NewSessionContext(cleanup, session)
		_ = cl.Database(t.Database).RunCommand(cleanup, bson.D{{Key: "killCursors", Value: collection}, {Key: "cursors", Value: bson.A{cursorID}}}).Err()
	}()
	if ctx.Err() != nil {
		return failure(out, ctx.Err(), ctx, budget)
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
	raw, e := cl.Database(t.Database).RunCommand(ctx, command).Raw()
	if e != nil {
		return failure(out, e, ctx, budget)
	}
	if e = writeError(raw); e != nil {
		return failure(out, e, ctx, budget)
	}
	docs := []bson.Raw{}
	if cursors[verb] {
		first := true
		for {
			cursor, ok := raw.Lookup("cursor").DocumentOK()
			if !ok {
				return failure(out, sqlclient.ErrUnavailable, ctx, budget)
			}
			cursorID, ok = cursor.Lookup("id").AsInt64OK()
			if !ok {
				return failure(out, sqlclient.ErrUnavailable, ctx, budget)
			}
			ns, ok := cursor.Lookup("ns").StringValueOK()
			prefix := t.Database + "."
			if !ok || !strings.HasPrefix(ns, prefix) || len(ns) <= len(prefix) {
				return failure(out, sqlclient.ErrDenied, ctx, budget)
			}
			collection = strings.TrimPrefix(ns, prefix)
			if strings.ContainsRune(collection, 0) {
				return failure(out, sqlclient.ErrDenied, ctx, budget)
			}
			batch := "nextBatch"
			if first {
				batch = "firstBatch"
				first = false
			}
			array, ok := cursor.Lookup(batch).ArrayOK()
			if !ok {
				return failure(out, sqlclient.ErrUnavailable, ctx, budget)
			}
			values, e := array.Values()
			if e != nil {
				return failure(out, e, ctx, budget)
			}
			for _, value := range values {
				doc, ok := value.DocumentOK()
				if !ok {
					return failure(out, sqlclient.ErrUnavailable, ctx, budget)
				}
				docs = append(docs, doc)
				if len(docs) > in.RowLimit {
					out.Truncated = true
					out.ErrorCode = "result_limit"
					return out, sqlclient.ErrResultLimit
				}
			}
			if cursorID == 0 {
				break
			}
			if authorize != nil && authorize() != nil {
				out.ErrorCode = "access_revoked"
				return out, sqlclient.ErrDenied
			}
			raw, e = cl.Database(t.Database).RunCommand(cursorContext{ctx}, bson.D{{Key: "getMore", Value: cursorID}, {Key: "collection", Value: collection}, {Key: "batchSize", Value: int32(min(in.RowLimit-len(docs)+1, 1000))}}).Raw()
			if e != nil {
				return failure(out, e, ctx, budget)
			}
		}
	} else {
		docs = append(docs, raw)
	}
	if e = table(&out, docs, in.RowLimit); e != nil {
		return failure(out, e, ctx, budget)
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
		for _, key := range []string{"nModified", "n"} {
			if count, ok := raw.Lookup(key).AsInt64OK(); ok {
				out.AffectedRows = count
				known = true
				break
			}
		}
		out.AffectedRowsKnown = &known
	}
	return out, nil
}
func writeError(raw bson.Raw) error {
	if errors, ok := raw.Lookup("writeErrors").ArrayOK(); ok {
		values, e := errors.Values()
		if e != nil {
			return e
		}
		if len(values) > 0 {
			if first, ok := values[0].DocumentOK(); ok {
				code, _ := first.Lookup("code").AsInt64OK()
				return mongo.CommandError{Code: int32(code)}
			}
			return sqlclient.ErrUnavailable
		}
	}
	if concern, ok := raw.Lookup("writeConcernError").DocumentOK(); ok {
		code, _ := concern.Lookup("code").AsInt64OK()
		return mongo.CommandError{Code: int32(code)}
	}
	return nil
}
func cell(value bson.RawValue) (*string, error) {
	if value.Type == bson.TypeNull {
		return nil, nil
	}
	var text string
	switch value.Type {
	case bson.TypeString:
		text = value.StringValue()
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			text = "0x" + hex.EncodeToString([]byte(text))
		}
	case bson.TypeInt32:
		text = strconv.FormatInt(int64(value.Int32()), 10)
	case bson.TypeInt64:
		text = strconv.FormatInt(value.Int64(), 10)
	case bson.TypeDouble:
		text = strconv.FormatFloat(value.Double(), 'g', -1, 64)
	case bson.TypeBoolean:
		text = strconv.FormatBool(value.Boolean())
	default:
		text = value.String()
	}
	return &text, nil
}
func table(out *Result, docs []bson.Raw, limit int) error {
	if len(docs) > limit {
		return sqlclient.ErrResultLimit
	}
	columns := map[string]int{}
	total, cells := 0, 0
	for _, doc := range docs {
		elements, e := doc.Elements()
		if e != nil {
			return e
		}
		for _, element := range elements {
			key := element.Key()
			if _, ok := columns[key]; !ok {
				total += len(key)
				if len(key) > sqlclient.MaxCellBytes || total > sqlclient.MaxResultBytes {
					return sqlclient.ErrResultLimit
				}
				columns[key] = len(columns)
				out.Columns = append(out.Columns, sqlclient.Column{Name: key, DatabaseType: element.Value().Type.String()})
			}
		}
	}
	if len(columns)*len(docs) > sqlclient.MaxResultCells {
		return sqlclient.ErrResultLimit
	}
	for rowIndex, doc := range docs {
		row := make([]*string, len(columns))
		present := make([]bool, len(columns))
		elements, e := doc.Elements()
		if e != nil {
			return e
		}
		for _, element := range elements {
			cells++
			if cells > sqlclient.MaxResultCells {
				return sqlclient.ErrResultLimit
			}
			value, e := cell(element.Value())
			if e != nil {
				return e
			}
			if value != nil {
				if len(*value) > sqlclient.MaxCellBytes {
					v := (*value)[:sqlclient.MaxCellBytes]
					for !utf8.ValidString(v) {
						v = v[:len(v)-1]
					}
					value = &v
					out.Truncated = true
				}
				total += len(*value)
				if total > sqlclient.MaxResultBytes {
					return sqlclient.ErrResultLimit
				}
			}
			row[columns[element.Key()]] = value
			present[columns[element.Key()]] = true
		}
		for index, exists := range present {
			if !exists {
				out.MissingCells = append(out.MissingCells, [2]int{rowIndex, index})
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return nil
}
