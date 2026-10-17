package agentevents

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxNotificationAlerts = 20000

type notificationAlert struct {
	ID          string
	Index       uint64
	Source      Source
	CollectorID string
	State       string
	At          time.Time
}
type notificationIndex struct {
	Version  int
	Boundary uint64
	Alerts   []notificationAlert
}

func cloneNotificationIndex(v *notificationIndex) *notificationIndex {
	if v == nil {
		return nil
	}
	out := *v
	out.Alerts = slices.Clone(v.Alerts)
	return &out
}
func alertID(a notificationAlert) string { a.ID = ""; return eventfeed.Digest(a) }
func (s *Store) initializeNotifications() error {
	if s.namespace != "agent-events" {
		return nil
	}
	if s.data.Notifications == nil {
		s.data.Notifications = &notificationIndex{Version: 1, Boundary: s.data.Total, Alerts: []notificationAlert{}}
		return s.saveIndex(&s.data)
	}
	v := s.data.Notifications
	if v.Version != 1 || v.Boundary > s.data.Total || len(v.Alerts) > maxNotificationAlerts {
		return ErrInvalid
	}
	previous := v.Boundary
	for _, a := range v.Alerts {
		if a.Index <= previous || a.Index > s.data.Total || a.ID != alertID(a) || !validSource(a.Source) || a.CollectorID == "" || a.At.IsZero() || !notificationState(a.State) {
			return ErrInvalid
		}
		previous = a.Index
	}
	return nil
}
func notificationState(v string) bool {
	return slices.Contains([]string{"agent_repair_completed", "agent_repair_failed", "agent_repair_interrupted", "agent_history_gap", "agent_stream_changed", "agent_log_missing"}, v)
}
func addNotificationAlert(next *index, r Record) {
	if next.Notifications == nil {
		return
	}
	state := ""
	switch r.Kind {
	case "host_event":
		if r.Event != nil && slices.Contains([]string{"repair_completed", "repair_failed", "repair_interrupted"}, r.Event.Kind) {
			state = "agent_" + r.Event.Kind
		}
	case "history_gap":
		state = "agent_history_gap"
	case "stream_changed":
		state = "agent_stream_changed"
	case "journal_missing":
		state = "agent_log_missing"
	}
	if state == "" {
		return
	}
	a := notificationAlert{Index: r.Index, Source: r.Source, CollectorID: r.Collector.ID, State: state, At: r.ObservedAt}
	a.ID = alertID(a)
	next.Notifications.Alerts = append(next.Notifications.Alerts, a)
}
func pruneNotificationAlerts(next *index, now time.Time) {
	if next.Notifications == nil {
		return
	}
	list := next.Notifications.Alerts
	remove := 0
	cutoff := now.Add(-30 * 24 * time.Hour)
	for remove < len(list) && (len(list)-remove > maxNotificationAlerts || list[remove].At.Before(cutoff)) {
		remove++
	}
	if remove > 0 {
		next.Notifications.Boundary = list[remove-1].Index
		list = slices.Clone(list[remove:])
	}
	next.Notifications.Alerts = list
}

// NotificationFeed reads only the compact encrypted alert index. It never
// scans collection receipts, command output, configurations or remote IP lists.
// Legacy archives remain readable; notification indexing starts at upgrade.
func (s *Store) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return eventfeed.Batch{}, e
	}
	if s.data.Notifications == nil || limit < 1 || limit > 100 {
		return eventfeed.Batch{}, ErrInvalid
	}
	list := s.data.Notifications.Alerts
	if len(list) > 0 && list[len(list)-1].ID == after {
		return eventfeed.Batch{Events: []eventfeed.Event{}, Cursor: after}, nil
	}
	start := 0
	gap := after != ""
	if after != "" {
		for i, a := range list {
			if a.ID == after {
				start = i + 1
				gap = false
				break
			}
		}
	}
	out := eventfeed.Batch{Events: []eventfeed.Event{}, Cursor: after, Gap: gap}
	for _, a := range list[start:] {
		if ctx.Err() != nil {
			return eventfeed.Batch{}, ctx.Err()
		}
		out.Cursor = a.ID
		if a.At.Before(since) {
			continue
		}
		out.Events = append(out.Events, eventfeed.Event{ID: a.ID, Kind: "agent-events", ResourceID: "agent-event-" + strconv.FormatUint(a.Index, 10), OwnerID: a.CollectorID, Name: eventfeed.MetadataText(a.Source.AssetName, 480), State: a.State, At: a.At})
		if len(out.Events) == limit {
			break
		}
	}
	return out, nil
}

type NotificationSource struct {
	Source
	CollectorID, State string
	ObservedAt         time.Time
}

var ErrNotificationNotFound = errors.New("agent notification source not found")

func (s *Store) NotificationSource(id string) (NotificationSource, error) {
	const prefix = "agent-event-"
	value := strings.TrimPrefix(id, prefix)
	n, e := strconv.ParseUint(value, 10, 53)
	if e != nil || n == 0 || id != prefix+strconv.FormatUint(n, 10) {
		return NotificationSource{}, ErrNotificationNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return NotificationSource{}, e
	}
	if n > s.data.Total {
		return NotificationSource{}, ErrNotificationNotFound
	}
	if s.data.Notifications != nil {
		list := s.data.Notifications.Alerts
		i := sort.Search(len(list), func(i int) bool { return list[i].Index >= n })
		if i < len(list) && list[i].Index == n {
			a := list[i]
			return NotificationSource{a.Source, a.CollectorID, a.State, a.At}, nil
		}
	}
	rows, e := s.segment((n - 1) / segmentSize)
	if e != nil {
		return NotificationSource{}, e
	}
	r := rows[(n-1)%segmentSize]
	state := ""
	if r.Kind == "host_event" && r.Event != nil && notificationState("agent_"+r.Event.Kind) {
		state = "agent_" + r.Event.Kind
	}
	switch r.Kind {
	case "history_gap":
		state = "agent_history_gap"
	case "stream_changed":
		state = "agent_stream_changed"
	case "journal_missing":
		state = "agent_log_missing"
	}
	return NotificationSource{Source: r.Source, CollectorID: r.Collector.ID, State: state, ObservedAt: r.ObservedAt}, nil
}
