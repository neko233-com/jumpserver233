// Package eventfeed provides bounded metadata feeds for durable notifications.
package eventfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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

// MetadataText keeps user-provided resource labels from stalling a metadata
// feed. It does not alter the authoritative resource or its audit record.
func MetadataText(v string, max int) string {
	if max <= 0 {
		return ""
	}
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(v, "�"))
	v = strings.TrimSpace(v)
	if len(v) > max {
		v = v[:max]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// Snapshot revisits surviving records after each complete pass. Late inserts
// and changing reviewer memberships cannot be skipped by a time cursor.
// Removal is expected in pending queues and does not imply an audit gap.
func Snapshot(rows []Event, after string, since time.Time, limit int) Batch {
	out := Batch{Events: []Event{}}
	if limit < 1 || limit > 100 {
		return out
	}
	// Callers provide events sorted by ID.
	for _, e := range rows {
		if e.ID <= after {
			continue
		}
		if len(out.Events) == limit {
			return out
		}
		out.Cursor = e.ID
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		out.Events = append(out.Events, e)
	}
	out.Cursor = ""
	return out
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
