package hostplugins_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountDiscoveryBoundsConcurrentConnectionsAndReleasesOnCancellation(t *testing.T) {
	entered := make(chan string, 8)
	done := make(chan error, 4)
	s := hostplugins.New(func(ctx context.Context, id string) (hostplugins.Transport, error) {
		entered <- id
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := func() error { return nil }
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("asset-%d", i)
		go func() { _, _, e := s.DiscoverAccounts(ctx, id, "job-"+strings.Repeat("a", 32), guard); done <- e }()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("collector did not reserve a slot")
		}
	}
	_, _, e := s.DiscoverAccounts(ctx, "asset-0", "job-"+strings.Repeat("b", 32), guard)
	assert.ErrorIs(t, e, hostplugins.ErrConflict)
	_, _, e = s.DiscoverAccounts(ctx, "asset-overflow", "job-"+strings.Repeat("b", 32), guard)
	assert.ErrorIs(t, e, hostplugins.ErrConflict)
	cancel()
	for i := 0; i < 4; i++ {
		select {
		case e := <-done:
			require.ErrorIs(t, e, context.Canceled)
		case <-time.After(time.Second):
			t.Fatal("cancelled collector retained a slot")
		}
	}
	short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	_, _, e = s.DiscoverAccounts(short, "asset-next", "job-"+strings.Repeat("c", 32), guard)
	assert.ErrorIs(t, e, context.DeadlineExceeded)
	denied := errors.New("synthetic revoked role")
	_, _, e = s.DiscoverAccounts(context.Background(), "asset-next", "job-"+strings.Repeat("d", 32), func() error { return denied })
	assert.ErrorIs(t, e, denied)
}
