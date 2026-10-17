package desktop

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/sessionpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pngDisplay struct {
	fakeDisplay
	png []byte
}

func (d *pngDisplay) Snapshot() (rdpclient.Frame, error) {
	return rdpclient.Frame{Sequence: 1, Width: 320, Height: 200, PNG: d.png}, nil
}
func TestDesktopSecurityExpiryAndBurnedWatermarkCache(t *testing.T) {
	for _, duration := range []bool{true, false} {
		t.Run(map[bool]string{true: "duration", false: "idle"}[duration], func(t *testing.T) {
			b, e := New(t.TempDir(), make([]byte, 32))
			require.NoError(t, e)
			defer b.CloseAll()
			var pngData bytes.Buffer
			require.NoError(t, png.Encode(&pngData, image.NewRGBA(image.Rect(0, 0, 320, 200))))
			d := &pngDisplay{fakeDisplay: fakeDisplay{done: make(chan struct{})}, png: pngData.Bytes()}
			settings := sessionpolicy.Settings{Watermark: true, IdleMinutes: 1}
			if duration {
				settings = sessionpolicy.Settings{Watermark: true, MaxHours: 1}
			}
			b.SetSessionPolicy(func() sessionpolicy.Settings { return settings })
			s, e := b.Create(context.Background(), Request{Record: Record{AssetID: "qa", OperatorID: "user-123"}, Open: func(context.Context) (Display, error) { return d, nil }, Guard: func(context.Context, string) error { return nil }})
			require.NoError(t, e)
			b.mu.Lock()
			live := b.live[s.ID]
			b.mu.Unlock()
			first, e := live.snapshot()
			require.NoError(t, e)
			second, e := live.snapshot()
			require.NoError(t, e)
			assert.Equal(t, first.PNG, second.PNG)
			assert.NotEqual(t, d.png, first.PNG)
			stored, e := b.Frame(s.ID, "user-123", false, 0)
			require.NoError(t, e)
			assert.Equal(t, first.PNG, stored)
			live.mu.Lock()
			live.lastInput = time.Now().Add(-2 * time.Minute)
			if duration {
				live.record.StartedAt = time.Now().Add(-2 * time.Hour)
			}
			live.mu.Unlock()
			want := "idle_timeout"
			if duration {
				want = "duration_limit"
			}
			require.Eventually(t, func() bool {
				record, e := b.Get(s.ID, "user-123", false)
				return e == nil && record.Status == "ended" && record.EndReason == want
			}, 2*time.Second, time.Millisecond)
		})
	}
}

func BenchmarkWatermarkedFrame(b *testing.B) {
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 1280, 720))); err != nil {
		b.Fatal(err)
	}
	d := &pngDisplay{fakeDisplay: fakeDisplay{done: make(chan struct{})}, png: data.Bytes()}
	a := &active{display: d, record: Record{Watermark: "JMS user-123 | session-456"}}
	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := sessionpolicy.StampPNG(data.Bytes(), a.record.Watermark); err != nil {
				b.Fatal(err)
			}
		}
	})
	if _, err := a.snapshot(); err != nil {
		b.Fatal(err)
	}
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := a.snapshot(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
