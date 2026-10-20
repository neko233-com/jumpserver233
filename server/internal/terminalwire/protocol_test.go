package terminalwire

import (
	"bytes"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"
)

type partialWriter struct{ bytes.Buffer }

func (w *partialWriter) Write(v []byte) (int, error) {
	if len(v) > 3 {
		v = v[:3]
	}
	return w.Buffer.Write(v)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestDirectoryTerminalWireBoundsAndPartialIO(t *testing.T) {
	f := Frame{Kind: Commit, ID: 42, Payload: []byte("pwd\r")}
	var w partialWriter
	require.NoError(t, Write(&w, f))
	got, e := Read(&w)
	require.NoError(t, e)
	assert.Equal(t, f, got)
	assert.ErrorIs(t, Write(zeroWriter{}, f), io.ErrShortWrite)
	assert.ErrorIs(t, Write(io.Discard, Frame{Payload: make([]byte, MaxPayload+1)}), ErrProtocol)
	var header [13]byte
	binary.BigEndian.PutUint32(header[:4], MaxPayload+1)
	_, e = Read(bytes.NewReader(header[:]))
	assert.ErrorIs(t, e, ErrProtocol)
	_, e = Read(bytes.NewReader([]byte{0, 0, 0}))
	assert.ErrorIs(t, e, io.ErrUnexpectedEOF)
}
func TestDirectoryTerminalProofNeverAcceptsClientPWDOrPathAliases(t *testing.T) {
	p := Proof{Root: "/srv/work", Directory: "/srv/work/sub", RootIdentity: strings.Repeat("a", 64), DirectoryIdentity: strings.Repeat("b", 64)}
	assert.True(t, p.Valid())
	for _, directory := range []string{"", "/srv/work/../work/sub", "/srv/work-other", "/srv/work/sub\n", "/srv/work\\sub", "/etc"} {
		bad := p
		bad.Directory = directory
		assert.False(t, bad.Valid(), directory)
	}
	p.DirectoryIdentity = "client-pwd"
	assert.False(t, p.Valid())
}
