// Package eventfeed provides bounded metadata feeds for durable notifications.
package eventfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Event struct {
	ID         string
	Kind       string
	ResourceID string
	OwnerID    string
	ActorID    string
	Name       string
	State      string
	Revision   int
	At         time.Time
}
type Batch struct {
	Events []Event
	Cursor string
	Gap    bool
}

func Digest(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// Rows are in durable publication order. A missing retained anchor is explicit;
// callers can surface the retention gap while processing surviving events.
func Read(rows []Event, after string, since time.Time, limit int) Batch {
	out := Batch{Events: []Event{}, Cursor: after}
	if limit < 1 || limit > 100 {
		return out
	}
	start := 0
	if after != "" {
		found := false
		for i, e := range rows {
			if e.ID == after {
				start = i + 1
				found = true
				break
			}
		}
		out.Gap = !found
	}
	for _, e := range rows[start:] {
		out.Cursor = e.ID
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		out.Events = append(out.Events, e)
		if len(out.Events) == limit {
			break
		}
	}
	return out
}
