package notifications

import (
	"context"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudnotify"
)

// MFARevision and SendMFA expose only the native SMS transport to the platform
// factor service. Login codes never enter the notification message/outbox store.
func (s *Service) MFARevision() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Config
	if s.closed || !c.SMS.Enabled || !cloudnotify.SMSKind(c.SMS.Provider) || c.Validate() != nil {
		return 0
	}
	return c.Revision
}
func (s *Service) SendMFA(ctx context.Context, revision int, phone, id, code string, check func() error) cloudnotify.Outcome {
	s.mu.Lock()
	cfg := s.data.Config
	if s.closed || cfg.Revision != revision || !cfg.SMS.Enabled || !cloudnotify.SMSKind(cfg.SMS.Provider) {
		s.mu.Unlock()
		return cloudnotify.Outcome{State: "failed", Code: "configuration_changed"}
	}
	s.wg.Add(1)
	cfg.Settings = cloneSettings(cfg.Settings)
	lifetime := s.ctx
	s.mu.Unlock()
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(lifetime, cancel)
	defer stop()
	verify := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if s.MFARevision() != revision {
			return ErrConflict
		}
		if check != nil {
			return check()
		}
		return nil
	}
	if verify() != nil {
		return cloudnotify.Outcome{State: "suppressed", Code: "configuration_changed"}
	}
	return cloudnotify.New().SendSMS(ctx, cfg.SMS.Provider, cfg.SMS.NativeSMS, cfg.SMSSecret, cfg.SMS.CA, phone, id, true, map[string]string{"code": code}, verify)
}
