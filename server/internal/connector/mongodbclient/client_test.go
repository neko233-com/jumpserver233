package mongodbclient

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"io"
	"net"
	"strings"
	"testing"
)

func query(raw string, ro bool) Input {
	return Input{SQL: raw, ReadOnly: ro, RowLimit: 100, TimeoutSeconds: 5}
}
func TestMongoPolicyRejectsWritesHiddenPipelinesAndIdentityOverrides(t *testing.T) {
	for _, raw := range []string{`{"insert":"items","documents":[{}]}`, `{"aggregate":"items","pipeline":[{"$facet":{"x":[{"$merge":"items"}]}}],"cursor":{}}`, `{"explain":{"delete":"items","deletes":[{"q":{},"limit":0}]}}`, `{"find":"items","filter":{"$where":"return true"}}`} {
		_, _, e := prepare(query(raw, true), "qa", true)
		assert.ErrorIs(t, e, sqlclient.ErrDenied)
	}
	for _, raw := range []string{`{"createUser":"x","pwd":"private"}`, `{"find":"items","$db":"foreign"}`, `{"find":"items","lsid":{}}`, `{"getMore":1,"collection":"items"}`} {
		_, _, e := prepare(query(raw, false), "qa", false)
		assert.ErrorIs(t, e, sqlclient.ErrInvalid)
	}
	for _, raw := range []string{`{"aggregate":"items","pipeline":[{"$out":{"db":"foreign","coll":"x"}}]}`, `{"aggregate":"items","pipeline":[{"$lookup":{"from":{"db":"foreign","coll":"x"},"as":"x"}}]}`} {
		_, _, e := prepare(query(raw, false), "qa", false)
		assert.ErrorIs(t, e, sqlclient.ErrDenied)
	}
	cmd, verb, e := prepare(query(`{"find":"items","filter":{"a":1},"batchSize":100000,"maxTimeMS":9999999}`, true), "qa", true)
	require.NoError(t, e)
	assert.Equal(t, "find", verb)
	assert.Equal(t, "find", cmd[0].Key)
	assert.Contains(t, cmd, bson.E{Key: "batchSize", Value: int32(101)})
	for _, field := range cmd {
		assert.NotEqual(t, "maxTimeMS", field.Key)
	}
}
func TestMongoGuardRejectsTwoGigabyteHeaderBeforeDriverAllocation(t *testing.T) {
	for _, size := range []uint32{0x7fffffff, MaxWireBytes + 1, 15} {
		a, b := net.Pipe()
		budget := &wireBudget{}
		budget.remaining.Store(MaxWireBytes)
		guard := messageConnection{Conn: a, budget: budget}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			var h [16]byte
			binary.LittleEndian.PutUint32(h[:4], size)
			binary.LittleEndian.PutUint32(h[12:], 2013)
			b.Write(h[:])
		}()
		var sizeOnly [4]byte
		n, e := guard.Read(sizeOnly[:])
		require.Error(t, e)
		assert.Zero(t, n)
		if size > MaxWireBytes {
			assert.ErrorIs(t, e, sqlclient.ErrResultLimit)
			assert.True(t, budget.exceeded.Load())
		}
		a.Close()
		<-done
	}
}
func TestMongoGuardStreamsMultipleFramesAndRejectsCompression(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		a, b := net.Pipe()
		budget := &wireBudget{}
		budget.remaining.Store(MaxWireBytes)
		guard := messageConnection{Conn: a, budget: budget}
		go func() {
			defer b.Close()
			var h [16]byte
			binary.LittleEndian.PutUint32(h[:4], 20)
			opcode := uint32(2013)
			if compressed {
				opcode = 2012
			}
			binary.LittleEndian.PutUint32(h[12:], opcode)
			b.Write(append(h[:], []byte("body")...))
			if !compressed {
				b.Write(append(h[:], []byte("body")...))
			}
		}()
		if compressed {
			_, e := guard.Read(make([]byte, 4))
			assert.Error(t, e)
		} else {
			raw, e := io.ReadAll(&guard)
			require.NoError(t, e)
			assert.Len(t, raw, 40)
		}
		a.Close()
	}
}
func TestMongoNullExtendedTypesTableLimitsAndSanitizedErrors(t *testing.T) {
	raw, e := bson.Marshal(bson.D{{Key: "message", Value: "private-value"}, {Key: "optional", Value: nil}, {Key: "precise", Value: int64(9223372036854775807)}, {Key: "binary", Value: bson.Binary{Subtype: 0, Data: []byte{0, 255}}}})
	require.NoError(t, e)
	var out Result
	require.NoError(t, table(&out, []bson.Raw{raw}, 5))
	assert.Equal(t, "private-value", *out.Rows[0][0])
	assert.Nil(t, out.Rows[0][1])
	assert.Equal(t, "9223372036854775807", *out.Rows[0][2])
	assert.Contains(t, *out.Rows[0][3], "$binary")
	budget := &wireBudget{}
	out, e = failure(Result{}, errors.New("private-database-error"), context.Background(), budget)
	assert.Error(t, e)
	assert.NotContains(t, e.Error(), "private")
	raw, e = bson.Marshal(bson.D{{Key: "x", Value: strings.Repeat("中", 4000)}})
	require.NoError(t, e)
	out = Result{}
	require.NoError(t, table(&out, []bson.Raw{raw}, 1))
	assert.True(t, out.Truncated)
	assert.LessOrEqual(t, len(*out.Rows[0][0]), sqlclient.MaxCellBytes)
}

func TestMongoWriteErrorCodesArePreservedWithoutErrorBodies(t *testing.T) {
	budget := &wireBudget{}
	for _, cause := range []error{mongo.WriteException{WriteErrors: mongo.WriteErrors{{Code: 11000, Message: "private-document"}}}, mongo.BulkWriteException{WriteErrors: []mongo.BulkWriteError{{WriteError: mongo.WriteError{Code: 11000, Message: "private-document"}}}}} {
		out, e := failure(Result{Transaction: "unknown"}, cause, context.Background(), budget)
		assert.Equal(t, "11000", out.DatabaseCode)
		assert.Equal(t, "unknown", out.Transaction)
		assert.NotContains(t, e.Error(), "private")
	}
}
