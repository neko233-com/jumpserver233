package mssql

import (
	"github.com/stretchr/testify/assert"
	"io"
	"sync/atomic"
	"testing"
)

type closeProbeTransport struct{ closed atomic.Bool }

func (c *closeProbeTransport) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *closeProbeTransport) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeProbeTransport) Close() error                { c.closed.Store(true); return nil }
func TestCloseNeverPoolsBuffersWhileResponseReaderIsActive(t *testing.T) {
	transport := &closeProbeTransport{}
	var pooled atomic.Bool
	done := make(chan struct{})
	conn := Conn{sess: &tdsSession{readDone: done, buf: &tdsBuffer{transport: transport, bufClose: func() { pooled.Store(true) }}}}
	assert.NoError(t, conn.Close())
	assert.True(t, transport.closed.Load())
	assert.False(t, pooled.Load())
	close(done)
	assert.False(t, pooled.Load())
}
func TestCloseRecyclesOnlyIdleBuffersAfterClosingTransport(t *testing.T) {
	for _, hasReader := range []bool{false, true} {
		transport := &closeProbeTransport{}
		var pooled atomic.Bool
		var done chan struct{}
		if hasReader {
			done = make(chan struct{})
			close(done)
		}
		conn := Conn{sess: &tdsSession{readDone: done, buf: &tdsBuffer{transport: transport, bufClose: func() { assert.True(t, transport.closed.Load()); pooled.Store(true) }}}}
		assert.NoError(t, conn.Close())
		assert.True(t, pooled.Load())
	}
}
