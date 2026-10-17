package gateway

import (
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
)

var errSessionIdle = errors.New("terminal idle timeout")
var errSessionDuration = errors.New("terminal duration limit")

// SetSessionPolicy is an explicit startup operation; policies are evaluated from
// the current store, while watermark identity is captured at session creation.
func (b *Broker) SetSessionPolicy(provider func() sessionpolicy.Settings) {
	b.mu.Lock()
	b.sessionPolicy = provider
	b.mu.Unlock()
}
func (b *Broker) securitySettings() sessionpolicy.Settings {
	b.mu.Lock()
	provider := b.sessionPolicy
	b.mu.Unlock()
	if provider != nil {
		return provider()
	}
	return sessionpolicy.Settings{}
}
func (b *Broker) sessionLimit(s *activeSession) error {
	settings := b.securitySettings()
	b.mu.Lock()
	started, last := s.startedAt, s.lastInput
	b.mu.Unlock()
	switch settings.EndReason(started, last, time.Now()) {
	case "idle_timeout":
		return errSessionIdle
	case "duration_limit":
		return errSessionDuration
	default:
		return nil
	}
}
func (b *Broker) touchSession(s *activeSession) { b.mu.Lock(); s.lastInput = time.Now(); b.mu.Unlock() }
