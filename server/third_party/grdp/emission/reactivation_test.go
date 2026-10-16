package emission

import (
	"sync/atomic"
	"testing"
)

func TestOnArmsOnceForNextPacket(t *testing.T) {
	e := NewEmitter()
	var count atomic.Int32
	e.On("data", func(value int) {
		if value == 1 {
			e.Once("data", func(int) { count.Add(1) })
		}
	})
	e.Emit("data", 1)
	if count.Load() != 0 {
		t.Fatal("reactivation listener consumed with deactivate packet")
	}
	e.Emit("data", 2)
	e.Emit("data", 3)
	if count.Load() != 1 {
		t.Fatal("listener did not run exactly once for next packet")
	}
}
func TestOnceRearmAndConcurrentDelivery(t *testing.T) {
	e := NewEmitter()
	var count atomic.Int32
	var handler func()
	handler = func() { count.Add(1); e.Once("data", handler) }
	e.Once("data", handler)
	e.Emit("data")
	if count.Load() != 1 {
		t.Fatal("first packet")
	}
	e.Emit("data")
	if count.Load() != 2 {
		t.Fatal("rearmed packet")
	}
}
