// Package terminalwire is the private, framed SSH helper transport. Public
// WebSocket clients continue to use the existing terminal frame protocol.
package terminalwire

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"strings"
	"unicode"
)

const MaxPayload = 64 * 1024
const (
	Input byte = 1 + iota
	Resize
	Acquire
	Commit
	Abort
)
const (
	Output byte = 16 + iota
	ProofResult
	Acknowledgement
	Hello
)

var ErrProtocol = errors.New("invalid private terminal frame")
var ErrUnverified = errors.New("terminal directory is not verified")

type Frame struct {
	Kind    byte
	ID      uint64
	Payload []byte
}

func Read(r io.Reader) (Frame, error) {
	var header [13]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(header[:4])
	if n > MaxPayload {
		return Frame{}, ErrProtocol
	}
	f := Frame{Kind: header[4], ID: binary.BigEndian.Uint64(header[5:]), Payload: make([]byte, n)}
	_, err := io.ReadFull(r, f.Payload)
	return f, err
}
func Write(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload {
		return ErrProtocol
	}
	var header [13]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(f.Payload)))
	header[4] = f.Kind
	binary.BigEndian.PutUint64(header[5:], f.ID)
	for _, raw := range [][]byte{header[:], f.Payload} {
		for len(raw) > 0 {
			n, err := w.Write(raw)
			if n < 0 || n > len(raw) {
				return ErrProtocol
			}
			raw = raw[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}

type Proof struct {
	Root              string `json:"root"`
	Directory         string `json:"directory"`
	RootIdentity      string `json:"root_identity"`
	DirectoryIdentity string `json:"directory_identity"`
}

func (p Proof) Valid() bool {
	validPath := func(v string) bool {
		return v != "" && len(v) <= 1024 && path.IsAbs(v) && path.Clean(v) == v && !strings.Contains(v, "\\") && strings.IndexFunc(v, unicode.IsControl) < 0
	}
	validHash := func(v string) bool {
		b, e := hex.DecodeString(v)
		return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
	}
	return validPath(p.Root) && p.Root != "/" && validPath(p.Directory) && (p.Directory == p.Root || strings.HasPrefix(p.Directory, p.Root+"/")) && validHash(p.RootIdentity) && validHash(p.DirectoryIdentity)
}

type Reply struct {
	Error string `json:"error,omitempty"`
	Proof Proof  `json:"proof"`
}
type Window struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}
type Lease interface {
	Proof() Proof
	Write([]byte) (int, error)
	Close() error
}
type DirectoryTerminal interface {
	AcquireDirectory(context.Context) (Lease, error)
}
