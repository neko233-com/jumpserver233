package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"os"
	"time"
)

// ReportMetadata folds the lifecycle index once, without reading command logs,
// recordings or checking every replay file. The report has an explicit IO bound.
func (b *Broker) ReportMetadata(ctx context.Context, owner string, all bool, emit func(reporting.Entry) error) error {
	b.auditMu.Lock()
	locked := true
	defer func() {
		if locked {
			b.auditMu.Unlock()
		}
	}()
	f, e := os.Open(b.auditPath)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() > 64<<20 {
		return reporting.ErrLimit
	}
	type item struct {
		at    time.Time
		state string
	}
	rows := map[string]item{}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var v struct {
			ID    string    `json:"session_id"`
			Owner string    `json:"operator_id"`
			Event string    `json:"event"`
			At    time.Time `json:"at"`
		}
		if json.Unmarshal(scan.Bytes(), &v) != nil || !validSessionID(v.ID) || v.At.IsZero() {
			return reporting.ErrInvalid
		}
		if v.Event == "started" && (all || owner != "" && v.Owner == owner) {
			if len(rows) >= reporting.MaxEntries {
				return reporting.ErrLimit
			}
			rows[v.ID] = item{v.At, "interrupted"}
		}
		if v.Event == "ended" {
			if r, ok := rows[v.ID]; ok {
				r.state = "ended"
				rows[v.ID] = r
			}
		}
	}
	if e = scan.Err(); e != nil {
		return e
	}
	// Never nest the lifecycle file lock with live-session/share locks.
	// Share audit callbacks can acquire auditMu while a share store is locked.
	b.auditMu.Unlock()
	locked = false
	b.mu.Lock()
	for id := range b.sessions {
		if v, ok := rows[id]; ok {
			v.state = "active"
			rows[id] = v
		}
	}
	b.mu.Unlock()
	for _, v := range rows {
		if e = emit(reporting.Entry{At: v.at, State: v.state}); e != nil {
			return e
		}
	}
	return nil
}
