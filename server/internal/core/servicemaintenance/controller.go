// Package servicemaintenance controls process-local admission before an upgrade.
// Stopped-service installation and the data OS lock remain authoritative.
package servicemaintenance

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/workgate"
)

var (
	ErrInvalid     = errors.New("invalid maintenance request")
	ErrConflict    = errors.New("maintenance revision or receipt conflict")
	ErrUnsupported = errors.New("maintenance requires standalone mode")
)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)

type Input struct {
	Instance  string `json:"instance"`
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
	Draining  bool   `json:"draining"`
}
type Event struct {
	Stopping  bool   `json:"stopping,omitempty"`
	Instance  string `json:"instance"`
	RequestID string `json:"request_id"`
	Revision  int    `json:"revision"`
	Draining  bool   `json:"draining"`
	ActorID   string `json:"actor_id"`
	Actor     string `json:"actor"`
}
type Status struct {
	Supported       bool           `json:"supported"`
	Instance        string         `json:"instance"`
	PID             int            `json:"pid"`
	Revision        int            `json:"revision"`
	Draining        bool           `json:"draining"`
	Ready           bool           `json:"ready"`
	Stopping        bool           `json:"stopping"`
	Activity        map[string]int `json:"activity"`
	ChangedAt       time.Time      `json:"changed_at"`
	Actor           string         `json:"actor"`
	Replayed        bool           `json:"replayed,omitempty"`
	AppliedRevision int            `json:"applied_revision,omitempty"`
}
type receipt struct {
	input    Input
	actor    string
	revision int
	stop     bool
}
type Controller struct {
	mu       sync.Mutex
	gate     *workgate.Gate
	status   Status
	receipts []receipt
	audit    func(Event) error
	activity func() map[string]int
	stop     func()
}

func (c *Controller) SetStop(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn == nil {
		c.stop = nil
		return
	}
	var once sync.Once
	c.stop = func() { once.Do(fn) }
}

func New(gate *workgate.Gate, supported bool, audit func(Event) error) (*Controller, error) {
	if gate == nil || audit == nil {
		return nil, ErrInvalid
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	return &Controller{gate: gate, audit: audit, status: Status{Supported: supported, Instance: hex.EncodeToString(nonce[:]), PID: os.Getpid(), Revision: 1}}, nil
}
func (c *Controller) Gate() *workgate.Gate { return c.gate }
func (c *Controller) SetActivity(fn func() map[string]int) {
	c.mu.Lock()
	c.activity = fn
	c.mu.Unlock()
}
func (c *Controller) Snapshot() Status {
	for {
		c.mu.Lock()
		out, activity := c.status, c.activity
		c.mu.Unlock()
		// Do not hold the controller lock while taking organization/service locks.
		out.Activity = c.gate.Snapshot()
		if activity != nil {
			for kind, count := range activity() {
				if count > 0 {
					out.Activity[kind] += count
				}
			}
		}
		c.mu.Lock()
		unchanged := c.status.Revision == out.Revision
		c.mu.Unlock()
		if !unchanged {
			continue
		}
		out.Ready = out.Draining && len(out.Activity) == 0
		return out
	}
}
func (c *Controller) Change(in Input, actorID, actor string) (Status, error) {
	if !requestID.MatchString(in.RequestID) || len(in.Instance) != 32 || in.Revision < 1 || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return Status{}, ErrInvalid
	}
	c.mu.Lock()
	if !c.status.Supported {
		c.mu.Unlock()
		return Status{}, ErrUnsupported
	}
	if in.Instance != c.status.Instance {
		c.mu.Unlock()
		return Status{}, ErrConflict
	}
	for _, receipt := range c.receipts {
		if receipt.input.RequestID != in.RequestID {
			continue
		}
		if receipt.input != in || receipt.actor != actorID || receipt.stop {
			c.mu.Unlock()
			return Status{}, ErrConflict
		}
		c.mu.Unlock()
		out := c.Snapshot()
		out.Replayed = true
		out.AppliedRevision = receipt.revision
		return out, nil
	}
	if in.Revision != c.status.Revision || c.status.Stopping {
		c.mu.Unlock()
		return Status{}, ErrConflict
	}
	if in.Draining != c.status.Draining {
		revision := c.status.Revision + 1
		if e := c.audit(Event{Instance: in.Instance, RequestID: in.RequestID, Revision: revision, Draining: in.Draining, ActorID: actorID, Actor: actor}); e != nil {
			c.mu.Unlock()
			return Status{}, e
		}
		c.gate.SetClosed(in.Draining)
		c.status.Revision = revision
		c.status.Draining = in.Draining
		c.status.ChangedAt = time.Now().UTC()
		c.status.Actor = actor
	}
	revision := c.status.Revision
	c.receipts = append(c.receipts, receipt{input: in, actor: actorID, revision: revision})
	if len(c.receipts) > 100 {
		c.receipts = c.receipts[len(c.receipts)-100:]
	}
	c.mu.Unlock()
	out := c.Snapshot()
	out.AppliedRevision = revision
	return out, nil
}

// Stop commits an irreversible process-local shutdown only after admission is
// closed and tracked work has finished. The caller invokes the returned callback
// after flushing the response. Cancellation cannot reopen a committed stop.
func (c *Controller) Stop(in Input, actorID, actor string) (Status, func(), error) {
	if !requestID.MatchString(in.RequestID) || len(in.Instance) != 32 || in.Revision < 1 || !in.Draining || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return Status{}, nil, ErrInvalid
	}
	snapshot := c.Snapshot()
	c.mu.Lock()
	if !c.status.Supported || c.stop == nil {
		c.mu.Unlock()
		return Status{}, nil, ErrUnsupported
	}
	if in.Instance != c.status.Instance {
		c.mu.Unlock()
		return Status{}, nil, ErrConflict
	}
	for _, r := range c.receipts {
		if r.input.RequestID != in.RequestID {
			continue
		}
		if r.input != in || r.actor != actorID || !r.stop {
			c.mu.Unlock()
			return Status{}, nil, ErrConflict
		}
		fn := c.stop
		c.mu.Unlock()
		out := c.Snapshot()
		out.Replayed = true
		out.AppliedRevision = r.revision
		return out, fn, nil
	}
	if in.Revision != c.status.Revision || snapshot.Revision != c.status.Revision || !snapshot.Ready || c.status.Stopping {
		c.mu.Unlock()
		return Status{}, nil, ErrConflict
	}
	revision := c.status.Revision + 1
	if e := c.audit(Event{Instance: in.Instance, RequestID: in.RequestID, Revision: revision, Draining: true, Stopping: true, ActorID: actorID, Actor: actor}); e != nil {
		c.mu.Unlock()
		return Status{}, nil, e
	}
	c.status.Revision = revision
	c.status.Stopping = true
	c.status.ChangedAt = time.Now().UTC()
	c.status.Actor = actor
	c.receipts = append(c.receipts, receipt{input: in, actor: actorID, revision: revision, stop: true})
	if len(c.receipts) > 100 {
		c.receipts = c.receipts[len(c.receipts)-100:]
	}
	fn := c.stop
	c.mu.Unlock()
	out := c.Snapshot()
	out.AppliedRevision = revision
	return out, fn, nil
}
