package gateway

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
)

type inputCheck struct {
	identity   inputIdentity
	submission commandSubmission
	policyKey  string
}

// Called with inputMu held, for the owner and every shared controller. An input
// lease stops the original shell until the audited decision is committed.
func beginDirectoryInput(ctx context.Context, s *activeSession, data []byte, actors ...inputIdentity) (io.Writer, func() error) {
	s.inputProof = terminalwire.Proof{}
	s.inputChecks = nil
	finish := func() error { s.inputProof = terminalwire.Proof{}; s.inputChecks = nil; return nil }
	needed := s.directoryPolicy != nil
	for _, a := range actors {
		needed = needed || a.DirectoryPolicy != nil
	}
	if !needed || len(data) > 2048 || !bytes.ContainsAny(data, "\r\n") {
		return s.terminal, finish
	}
	remote, ok := s.terminal.(terminalwire.DirectoryTerminal)
	if !ok {
		return s.terminal, finish
	}
	lease, err := remote.AcquireDirectory(ctx)
	if err != nil || lease == nil {
		return s.terminal, finish
	}
	if !lease.Proof().Valid() {
		_ = lease.Close()
		return s.terminal, finish
	}
	s.inputProof = lease.Proof()
	return lease, func() error { s.inputProof = terminalwire.Proof{}; s.inputChecks = nil; return lease.Close() }
}
func (b *Broker) writeTerminalInput(ctx context.Context, conn *websocket.Conn, s *activeSession, data []byte, actors ...inputIdentity) (err error) {
	writer, finish := beginDirectoryInput(ctx, s, data, actors...)
	defer func() {
		if e := finish(); err == nil {
			err = e
		}
	}()
	forward, e := b.prepareTerminalInput(ctx, conn, s, data, actors...)
	if e != nil {
		return e
	}
	if len(forward) == 0 {
		return nil
	}
	if e = s.recorder.Record('i', forward); e != nil {
		return e
	}
	if s.accessPolicy != nil && s.accessPolicy(ctx) != nil {
		return ErrSessionAccessDenied
	}
	for _, actor := range actors {
		if actor.Guard != nil {
			if e = actor.Guard(ctx); e != nil {
				return e
			}
		}
	}
	for _, check := range s.inputChecks {
		candidate := check.submission
		candidate.SubmittedAt = time.Now().UTC()
		current := decideInputPolicy(s, check.identity, candidate)
		if !current.Allowed || current.PolicyKey != check.policyKey {
			return ErrSessionAccessDenied
		}
	}
	if e = writeAll(writer, forward); e != nil {
		return e
	}
	b.touchSession(s)
	return nil
}
