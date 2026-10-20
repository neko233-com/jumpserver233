package sshclient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func directoryStreamFixture(t *testing.T, handler func(net.Conn, terminalwire.Frame) bool) (*directoryStream, terminalwire.Proof) {
	t.Helper()
	local, remote := net.Pipe()
	p := terminalwire.Proof{Root: "/srv/work", Directory: "/srv/work/app", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	s := newDirectoryStream(local, local, p.Root, p.RootIdentity, func() { _ = local.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer remote.Close()
		if terminalwire.Write(remote, terminalwire.Frame{Kind: terminalwire.Hello, Payload: []byte("jms233-directory-terminal-v1")}) != nil {
			return
		}
		for {
			f, e := terminalwire.Read(remote)
			if e != nil || !handler(remote, f) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		s.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("private helper fixture did not stop")
		}
		select {
		case <-s.done:
		case <-time.After(time.Second):
			t.Error("private terminal reader did not stop")
		}
	})
	select {
	case e := <-s.ready:
		require.NoError(t, e)
	case <-time.After(time.Second):
		t.Fatal("private terminal handshake timed out")
	}
	return s, p
}
func wireReply(c net.Conn, id uint64, kind byte, proof terminalwire.Proof) bool {
	raw, _ := json.Marshal(terminalwire.Reply{Proof: proof})
	return terminalwire.Write(c, terminalwire.Frame{Kind: kind, ID: id, Payload: raw}) == nil
}
func TestDirectoryTerminalCommitIsOneUseAndPreservesByteTransport(t *testing.T) {
	var commits atomic.Int32
	p := terminalwire.Proof{Root: "/srv/work", Directory: "/srv/work/app", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	s, _ := directoryStreamFixture(t, func(c net.Conn, f terminalwire.Frame) bool {
		switch f.Kind {
		case terminalwire.Acquire:
			return wireReply(c, f.ID, terminalwire.ProofResult, p)
		case terminalwire.Commit:
			commits.Add(1)
			return wireReply(c, f.ID, terminalwire.Acknowledgement, terminalwire.Proof{})
		case terminalwire.Resize:
			var v terminalwire.Window
			assert.NoError(t, json.Unmarshal(f.Payload, &v))
			assert.Equal(t, 120, v.Cols)
			return true
		default:
			t.Errorf("unexpected private frame %d", f.Kind)
			return false
		}
	})
	l, e := s.Acquire(t.Context())
	require.NoError(t, e)
	assert.Equal(t, p, l.Proof())
	_, e = s.Write([]byte("unbound\r"))
	assert.ErrorIs(t, e, terminalwire.ErrProtocol)
	for range 2 {
		n, e := l.Write([]byte("pwd\r"))
		require.NoError(t, e)
		assert.Equal(t, 4, n)
	}
	_, e = l.Write([]byte("other\r"))
	assert.ErrorIs(t, e, terminalwire.ErrProtocol)
	require.NoError(t, l.Close())
	assert.Equal(t, int32(1), commits.Load())
	require.NoError(t, s.Resize(120, 40))
}
func TestDirectoryTerminalLostCommitReceiptDoesNotRetry(t *testing.T) {
	var commits atomic.Int32
	p := terminalwire.Proof{Root: "/srv/work", Directory: "/srv/work/app", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	s, _ := directoryStreamFixture(t, func(c net.Conn, f terminalwire.Frame) bool {
		if f.Kind == terminalwire.Acquire {
			return wireReply(c, f.ID, terminalwire.ProofResult, p)
		}
		commits.Add(1)
		return false
	})
	l, e := s.Acquire(t.Context())
	require.NoError(t, e)
	_, e = l.Write([]byte("pwd\r"))
	require.Error(t, e)
	_, again := l.Write([]byte("pwd\r"))
	require.Error(t, again)
	assert.Equal(t, int32(1), commits.Load())
}
func TestDirectoryTerminalRejectsMismatchedRootsAndControlCancellationJoins(t *testing.T) {
	p := terminalwire.Proof{Root: "/srv/other", Directory: "/srv/other", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	s, _ := directoryStreamFixture(t, func(c net.Conn, f terminalwire.Frame) bool { return wireReply(c, f.ID, terminalwire.ProofResult, p) })
	_, e := s.Acquire(t.Context())
	assert.ErrorIs(t, e, terminalwire.ErrProtocol)
	hung, _ := directoryStreamFixture(t, func(c net.Conn, _ terminalwire.Frame) bool { var b [1]byte; _, _ = c.Read(b[:]); return false })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, e = hung.Acquire(ctx)
	require.Error(t, e)
}
func TestDirectoryTerminalOutputCannotForgeProofFrames(t *testing.T) {
	p := terminalwire.Proof{Root: "/srv/work", Directory: "/srv/work/app", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	var fake bytes.Buffer
	require.NoError(t, terminalwire.Write(&fake, terminalwire.Frame{Kind: terminalwire.ProofResult, ID: 999, Payload: []byte(`{"proof":{"directory":"/forged"}}`)}))
	s, _ := directoryStreamFixture(t, func(c net.Conn, f terminalwire.Frame) bool {
		if terminalwire.Write(c, terminalwire.Frame{Kind: terminalwire.Output, Payload: fake.Bytes()}) != nil {
			return false
		}
		return wireReply(c, f.ID, terminalwire.ProofResult, p)
	})
	output := make(chan []byte, 1)
	go func() { b := make([]byte, fake.Len()); _, _ = io.ReadFull(s.output, b); output <- b }()
	l, e := s.Acquire(t.Context())
	require.NoError(t, e)
	assert.Equal(t, p, l.Proof())
	assert.Equal(t, fake.Bytes(), <-output)
	// Close the fixture directly; no unconsumed lease may be forwarded as input.
	s.Close()
}
