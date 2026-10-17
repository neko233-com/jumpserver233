package notifications

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"path/filepath"
	"testing"
	"time"
)

func benchmarkStore(b *testing.B) *Service {
	b.Helper()
	s, e := Open(filepath.Join(b.TempDir(), "notifications.json"), make([]byte, 32), nil)
	if e != nil {
		b.Fatal(e)
	}
	b.Cleanup(s.Close)
	s.SetRunner(Runner{Principal: func(_ context.Context, id string) (Principal, error) {
		return Principal{Actor: Actor{ID: id, Name: "Synthetic benchmark"}}, nil
	}})
	for i := range 10000 {
		id := fmt.Sprintf("event-%05d", i)
		src := Source{Kind: "test", ID: id, EventID: eventfeed.Digest(id), Action: "test"}
		m := Message{ID: messageID(src, "system", "benchmark"), UserID: "benchmark", Inbox: true, Topic: "system", Name: "Synthetic benchmark event", State: "test", Source: src, At: time.Now().UTC(), Link: "/console/notifications"}
		s.data.Messages[m.ID] = m
		did := deliveryID(m.ID, "webhook")
		s.data.Deliveries[did] = delivery{Delivery: Delivery{ID: did, MessageID: m.ID, UserID: m.UserID, Channel: "webhook", State: "sent", Revision: 1, ConfigRevision: 1, CreatedAt: m.At, UpdatedAt: m.At}, Address: "https://capture.invalid/webhook", Message: m}
	}
	s.lastMaintenance = time.Now()
	return s
}
func BenchmarkNotificationInbox10000(b *testing.B) {
	s := benchmarkStore(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, e := s.Inbox(context.Background(), "benchmark", true, 0, 1); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkNotificationIdleTick10000(b *testing.B) {
	s := benchmarkStore(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.Tick()
	}
}
