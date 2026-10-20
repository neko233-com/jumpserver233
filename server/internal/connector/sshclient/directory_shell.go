package sshclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
)

type directoryStream struct {
	input           io.WriteCloser
	raw             io.ReadCloser
	output          *io.PipeReader
	outputWrite     *io.PipeWriter
	closeRemote     func()
	root, identity  string
	mu              sync.Mutex
	writes          sync.Mutex
	requests        sync.Mutex
	once            sync.Once
	done            chan struct{}
	ready           chan error
	sequence, lease uint64
	pending         map[uint64]chan terminalwire.Frame
}

func newDirectoryStream(in io.WriteCloser, raw io.ReadCloser, root, identity string, closeRemote func()) *directoryStream {
	r, w := io.Pipe()
	s := &directoryStream{input: in, raw: raw, output: r, outputWrite: w, root: root, identity: identity, closeRemote: closeRemote, done: make(chan struct{}), ready: make(chan error, 1), pending: map[uint64]chan terminalwire.Frame{}}
	go s.read()
	return s
}
func (s *directoryStream) read() {
	defer close(s.done)
	defer s.Close()
	hello := false
	for {
		f, e := terminalwire.Read(s.raw)
		if e != nil {
			return
		}
		if !hello {
			if f.Kind != terminalwire.Hello || f.ID != 0 || string(f.Payload) != "jms233-directory-terminal-v1" {
				s.ready <- terminalwire.ErrProtocol
				return
			}
			hello = true
			s.ready <- nil
			continue
		}
		switch f.Kind {
		case terminalwire.Output:
			if f.ID != 0 {
				return
			}
			if _, e = s.outputWrite.Write(f.Payload); e != nil {
				return
			}
		case terminalwire.ProofResult, terminalwire.Acknowledgement:
			s.mu.Lock()
			ch := s.pending[f.ID]
			s.mu.Unlock()
			if ch == nil {
				return
			}
			select {
			case ch <- f:
			default:
				return
			}
		default:
			return
		}
	}
}
func (s *directoryStream) Close() {
	s.once.Do(func() {
		s.closeRemote()
		_ = s.input.Close()
		_ = s.raw.Close()
		_ = s.output.Close()
		_ = s.outputWrite.Close()
	})
}
func (s *directoryStream) send(f terminalwire.Frame) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	select {
	case <-s.done:
		return io.ErrClosedPipe
	default:
	}
	if e := terminalwire.Write(s.input, f); e != nil {
		s.Close()
		return e
	}
	return nil
}
func (s *directoryStream) Write(data []byte) (int, error) {
	s.mu.Lock()
	locked := s.lease != 0
	s.mu.Unlock()
	if locked {
		return 0, terminalwire.ErrProtocol
	}
	if e := s.send(terminalwire.Frame{Kind: terminalwire.Input, Payload: data}); e != nil {
		return 0, e
	}
	return len(data), nil
}
func (s *directoryStream) Resize(cols, rows int) error {
	b, _ := json.Marshal(terminalwire.Window{Cols: cols, Rows: rows})
	return s.send(terminalwire.Frame{Kind: terminalwire.Resize, Payload: b})
}
func (s *directoryStream) control(ctx context.Context, kind byte, id uint64, payload []byte) (terminalwire.Reply, error) {
	s.requests.Lock()
	defer s.requests.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ch := make(chan terminalwire.Frame, 1)
	s.mu.Lock()
	if s.pending[id] != nil {
		s.mu.Unlock()
		return terminalwire.Reply{}, terminalwire.ErrProtocol
	}
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock() }()
	// Closing the SSH connection also interrupts a blocked frame write.
	stop := context.AfterFunc(ctx, s.Close)
	defer stop()
	if e := s.send(terminalwire.Frame{Kind: kind, ID: id, Payload: payload}); e != nil {
		return terminalwire.Reply{}, e
	}
	select {
	case f := <-ch:
		want := terminalwire.Acknowledgement
		if kind == terminalwire.Acquire {
			want = terminalwire.ProofResult
		}
		var reply terminalwire.Reply
		if f.Kind != want || json.Unmarshal(f.Payload, &reply) != nil {
			s.Close()
			return reply, terminalwire.ErrProtocol
		}
		if reply.Error != "" {
			if reply.Error != "directory_unverified" {
				s.Close()
			}
			return reply, terminalwire.ErrUnverified
		}
		return reply, nil
	case <-ctx.Done():
		s.Close()
		return terminalwire.Reply{}, ctx.Err()
	case <-s.done:
		return terminalwire.Reply{}, io.ErrClosedPipe
	}
}
func (s *directoryStream) Acquire(ctx context.Context) (terminalwire.Lease, error) {
	s.mu.Lock()
	if s.lease != 0 {
		s.mu.Unlock()
		return nil, terminalwire.ErrProtocol
	}
	s.sequence++
	id := s.sequence
	s.lease = id
	s.mu.Unlock()
	reply, e := s.control(ctx, terminalwire.Acquire, id, nil)
	if e != nil {
		s.mu.Lock()
		s.lease = 0
		s.mu.Unlock()
		return nil, e
	}
	if !reply.Proof.Valid() || reply.Proof.Root != s.root || reply.Proof.RootIdentity != s.identity {
		s.Close()
		return nil, terminalwire.ErrProtocol
	}
	return &directoryLease{stream: s, id: id, proof: reply.Proof}, nil
}

type directoryLease struct {
	mu       sync.Mutex
	stream   *directoryStream
	id       uint64
	proof    terminalwire.Proof
	finished bool
	hash     [32]byte
	n        int
	err      error
}

func (l *directoryLease) Proof() terminalwire.Proof { return l.proof }
func (l *directoryLease) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	hash := sha256.Sum256(data)
	if l.finished {
		if hash == l.hash {
			return l.n, l.err
		}
		return 0, terminalwire.ErrProtocol
	}
	l.finished = true
	l.hash = hash
	_, l.err = l.stream.control(context.Background(), terminalwire.Commit, l.id, data)
	l.stream.mu.Lock()
	l.stream.lease = 0
	l.stream.mu.Unlock()
	if l.err != nil {
		l.stream.Close()
		return 0, l.err
	}
	l.n = len(data)
	return l.n, nil
}
func (l *directoryLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return l.err
	}
	l.finished = true
	_, l.err = l.stream.control(context.Background(), terminalwire.Abort, l.id, nil)
	l.stream.mu.Lock()
	l.stream.lease = 0
	l.stream.mu.Unlock()
	if l.err != nil {
		l.stream.Close()
	}
	return l.err
}

// OpenDirectoryShellCommand starts the pinned helper without an outer SSH PTY.
// Its inner native PTY output cannot forge proof or acknowledgement frames.
func OpenDirectoryShellCommand(ctx context.Context, target Target, credentials Credentials, timeout time.Duration, startup, root, identity string) (*Shell, error) {
	if startup == "" || root == "" || identity == "" {
		return nil, terminalwire.ErrProtocol
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	setup, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, _, e := dial(setup, target, credentials, timeout)
	if e != nil {
		return nil, e
	}
	session, e := client.NewSession()
	if e != nil {
		_ = client.Close()
		return nil, e
	}
	closeRemote := func() { _ = client.Close(); _ = session.Close() }
	stop := context.AfterFunc(setup, closeRemote)
	input, e := session.StdinPipe()
	if e != nil {
		stop()
		closeRemote()
		return nil, e
	}
	raw, writer := io.Pipe()
	session.Stdout = writer
	session.Stderr = io.Discard
	if e = session.Start(startup); e != nil {
		stop()
		_ = input.Close()
		_ = raw.Close()
		_ = writer.Close()
		closeRemote()
		return nil, e
	}
	s := newDirectoryStream(input, raw, root, identity, closeRemote)
	shell := &Shell{framed: s, client: client, session: session, done: make(chan struct{})}
	go func() {
		err := session.Wait()
		shell.mu.Lock()
		shell.waitErr = err
		shell.mu.Unlock()
		_ = writer.CloseWithError(err)
		close(shell.done)
	}()
	select {
	case e = <-s.ready:
	case <-setup.Done():
		e = setup.Err()
	case <-s.done:
		e = errors.New("directory terminal handshake unavailable")
	}
	if e != nil || !stop() {
		s.Close()
		<-s.done
		if e == nil {
			e = setup.Err()
		}
		return nil, e
	}
	return shell, nil
}
