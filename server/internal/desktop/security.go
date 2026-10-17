package desktop

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
)

func (b *Broker) SetSessionPolicy(provider func() sessionpolicy.Settings) {
	b.mu.Lock()
	b.policy = provider
	b.mu.Unlock()
}
func (b *Broker) securitySettings() sessionpolicy.Settings {
	b.mu.Lock()
	provider := b.policy
	b.mu.Unlock()
	if provider != nil {
		return provider()
	}
	return sessionpolicy.Settings{MaxHours: 1}
}
func (a *active) snapshot() (rdpclient.Frame, error) {
	f, err := a.display.Snapshot()
	if err != nil {
		return f, err
	}
	if a.record.Watermark == "" {
		return f, nil
	}
	a.frameMu.Lock()
	defer a.frameMu.Unlock()
	if a.cached.Sequence == f.Sequence && len(a.cached.PNG) > 0 {
		return a.cached, nil
	}
	f.PNG, err = sessionpolicy.StampPNG(f.PNG, a.record.Watermark)
	if err != nil {
		return rdpclient.Frame{}, err
	}
	a.cached = f
	return f, nil
}
