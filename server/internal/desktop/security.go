package desktop

import (
	"encoding/binary"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
)

// Owner and viewers share one immutable wire packet for the same source frame.
// Slow viewers retain only the frame being written and do not queue old frames.
func (a *active) wireFrame() (uint64, []byte, error) {
	f, e := a.snapshot()
	if e != nil {
		return 0, nil, e
	}
	a.frameMu.Lock()
	defer a.frameMu.Unlock()
	if a.wireSequence < f.Sequence || len(a.wirePacket) == 0 {
		packet := make([]byte, 8+len(f.PNG))
		binary.BigEndian.PutUint64(packet, f.Sequence)
		copy(packet[8:], f.PNG)
		a.wireSequence, a.wirePacket = f.Sequence, packet
	}
	return a.wireSequence, a.wirePacket, nil
}

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
