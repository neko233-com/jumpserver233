// Package workgate admits and counts process-local operational work.
package workgate

import (
	"context"
	"errors"
	"sync"
)

var ErrDraining = errors.New("service is draining")

type Gate struct {
	mu     sync.Mutex
	closed bool
	active map[string]int
}

func New() *Gate { return &Gate{active: map[string]int{}} }

// Acquire and SetClosed share a lock: work is either counted or rejected.
// A nil gate preserves the connector's standalone library behavior.
func (g *Gate) Acquire(kind string) (func(), error) {
	_, release, e := g.Enter(context.Background(), kind)
	return release, e
}

type leaseKey struct{}
type lease struct {
	gate   *Gate
	active bool
}

// Enter lets an admitted operation finish its later handshakes (for example
// credential verification) while rejecting work with an expired parent lease.
func (g *Gate) Enter(ctx context.Context, kind string) (context.Context, func(), error) {
	if g == nil {
		return ctx, func() {}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	parent, _ := ctx.Value(leaseKey{}).(*lease)
	if g.closed && !(parent != nil && parent.gate == g && parent.active) {
		return ctx, nil, ErrDraining
	}
	g.active[kind]++
	l := &lease{gate: g, active: true}
	var once sync.Once
	return context.WithValue(WithGate(ctx, g), leaseKey{}, l), func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			l.active = false
			g.active[kind]--
			if g.active[kind] == 0 {
				delete(g.active, kind)
			}
		})
	}, nil
}

func (g *Gate) SetClosed(value bool) { g.mu.Lock(); g.closed = value; g.mu.Unlock() }
func (g *Gate) Closed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}
func (g *Gate) Snapshot() map[string]int {
	out := map[string]int{}
	if g == nil {
		return out
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for kind, count := range g.active {
		out[kind] = count
	}
	return out
}

type contextKey struct{}

func WithGate(ctx context.Context, g *Gate) context.Context {
	return context.WithValue(ctx, contextKey{}, g)
}
func FromContext(ctx context.Context) *Gate { g, _ := ctx.Value(contextKey{}).(*Gate); return g }
