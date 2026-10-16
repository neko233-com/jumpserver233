package redisclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func query(raw string, ro bool) Input {
	return Input{SQL: raw, ReadOnly: ro, RowLimit: 100, TimeoutSeconds: 5}
}
func TestRESPRejectsDeclaredAllocationNestedCountsAndMalformedFrames(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		limit bool
	}{{"$2147483647\r\n", true}, {"*2147483647\r\n", true}, {strings.Repeat("*1\r\n", 35) + "+OK\r\n", true}, {"$-2\r\n", false}, {"*wat\r\n", false}, {"$2\r\nx\r\n", false}, {"+bad\n", false}, {"?invalid\r\n", false}} {
		r := reader{reader: bufio.NewReaderSize(strings.NewReader(tc.raw), sqlclient.MaxCellBytes+2)}
		_, e := r.value(0)
		require.Error(t, e)
		if tc.limit {
			assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
		}
	}
}
func TestRESPNullEmptyBinaryArraysAndIntegerPrecision(t *testing.T) {
	r := reader{reader: bufio.NewReader(strings.NewReader("*5\r\n$-1\r\n$0\r\n\r\n$2\r\n\x00\xff\r\n:9223372036854775807\r\n*2\r\n$-1\r\n+OK\r\n"))}
	node, e := r.value(0)
	require.NoError(t, e)
	assert.True(t, node.items[0].null)
	kind, text, e := display(node.items[1])
	require.NoError(t, e)
	assert.Equal(t, "string", kind)
	assert.Empty(t, text)
	kind, text, e = display(node.items[2])
	require.NoError(t, e)
	assert.Equal(t, "binary", kind)
	assert.Equal(t, "0x00ff", text)
	assert.Equal(t, json.Number("9223372036854775807"), value(node.items[3]))
	kind, text, e = display(node.items[4])
	require.NoError(t, e)
	assert.Equal(t, "array", kind)
	assert.Equal(t, `[null,"OK"]`, text)
}
func TestReadOnlyPolicyAndSessionControlsRejectedBeforeConnection(t *testing.T) {
	target := Target{Settings: sqlclient.Settings{Database: "0", TLSMode: "verify-full"}}
	secret := Credentials{}
	for _, raw := range []string{`["SET","x","value"]`, `["SORT","x","STORE","y"]`, `["EVAL","return 1","0"]`, `["MEMORY","PURGE"]`} {
		out, e := Execute(context.Background(), target, secret, query(raw, true), nil)
		assert.ErrorIs(t, e, sqlclient.ErrDenied)
		assert.Equal(t, "not_started", out.Transaction)
	}
	for _, raw := range []string{`["AUTH","leaked"]`, `["SELECT","1"]`, `["CONFIG","GET","requirepass"]`, `["MULTI"]`, `["SUBSCRIBE","x"]`} {
		_, e := Execute(context.Background(), target, secret, query(raw, false), nil)
		assert.ErrorIs(t, e, sqlclient.ErrInvalid)
	}
	for _, raw := range []string{`["GET","x"]`, `["MEMORY","USAGE","x"]`, `["OBJECT","ENCODING","x"]`, `["SCAN","0"]`} {
		args, e := sqlclient.RedisCommand(raw)
		require.NoError(t, e)
		assert.True(t, ReadCommand(args))
	}
}
func TestRESPFailuresHideErrorBodyAndBoundConnection(t *testing.T) {
	for _, raw := range []string{"-WRONGTYPE private-value\r\n", "-PRIVATESECRET private-value\r\n"} {
		r := reader{reader: bufio.NewReader(strings.NewReader(raw))}
		_, e := r.value(0)
		require.Error(t, e)
		assert.NotContains(t, e.Error(), "private")
		out, e := failure(Result{}, e, context.Background())
		assert.NotContains(t, e.Error(), "private")
		assert.Contains(t, []string{"WRONGTYPE", "ERR"}, out.DatabaseCode)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := limitedConnection{Conn: a, remaining: 2}
	go func() { b.Write([]byte("abc")) }()
	buf := make([]byte, 4)
	n, e := c.Read(buf)
	require.NoError(t, e)
	assert.Equal(t, 2, n)
	_, e = c.Read(buf)
	assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
	assert.False(t, errors.Is(e, io.EOF))
}

type deadlineEdge struct{ context.Context }

func (deadlineEdge) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }
func TestSocketDeadlineBeforeContextTimerIsStillCancellation(t *testing.T) {
	out, e := failure(Result{Transaction: "unknown"}, errors.New("socket deadline"), deadlineEdge{context.Background()})
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	assert.Equal(t, "cancelled", out.ErrorCode)
	assert.Equal(t, "unknown", out.Transaction)
}
