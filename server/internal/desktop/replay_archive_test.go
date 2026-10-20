package desktop

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type closingReplayDisplay struct {
	*fakeDisplay
	entered, release chan struct{}
	closeOnce        sync.Once
}

func (d *closingReplayDisplay) Close() error {
	d.closeOnce.Do(func() { close(d.entered); <-d.release })
	return d.fakeDisplay.Close()
}
func TestReplayStorageDesktopCloseAllJoinsFinalization(t *testing.T) {
	b, e := New(t.TempDir(), make([]byte, 32))
	require.NoError(t, e)
	display := &closingReplayDisplay{fakeDisplay: &fakeDisplay{done: make(chan struct{})}, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(display.release) }) }
	defer release()
	t.Cleanup(b.CloseAll)
	created, e := b.Create(context.Background(), Request{Record: Record{AssetID: "asset", OperatorID: "owner"}, Open: func(context.Context) (Display, error) { return display, nil }, Guard: func(context.Context, string) error { return nil }})
	require.NoError(t, e)
	b.mu.Lock()
	active := b.live[created.ID]
	b.mu.Unlock()
	ended := make(chan struct{})
	go func() { b.end(active, "test"); close(ended) }()
	<-display.entered
	all := make(chan struct{})
	go func() { b.CloseAll(); close(all) }()
	select {
	case <-all:
		t.Fatal("CloseAll returned while finalized recording was still closing")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-all:
	case <-time.After(time.Second):
		t.Fatal("CloseAll did not join finalized recording")
	}
	<-ended
}
