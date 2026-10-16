package hostagent

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	EventFormat     = "jms233/agent-events/v1"
	JournalLimit    = 1024
	EventBatchLimit = 64
	MaxJournalBytes = 1 << 20
	MaxSequence     = 1<<53 - 1
)

var ErrJournal = errors.New("agent_event_journal_failed")

// Hash chaining detects corruption and gaps. A root-controlled reporting host
// is not an independent trust anchor or an authenticated platform operator.
type Event struct {
	Sequence     uint64    `json:"sequence"`
	ID           string    `json:"id"`
	Attempt      string    `json:"attempt"`
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	Trigger      string    `json:"trigger"`
	ConfigSHA    string    `json:"config_sha"`
	ActiveBans   int       `json:"active_bans"`
	ErrorCode    string    `json:"error_code,omitempty"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash,omitempty"`
}

type EventCursor struct {
	Stream   string `json:"stream"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}
type EventSnapshot struct {
	Format        string      `json:"format"`
	Stream        string      `json:"stream"`
	FirstSequence uint64      `json:"first_sequence"`
	LastSequence  uint64      `json:"last_sequence"`
	AnchorHash    string      `json:"anchor_hash"`
	Requested     EventCursor `json:"requested"`
	Events        []Event     `json:"events"`
	More          bool        `json:"more"`
	Missing       bool        `json:"missing"`
}

type eventJournal struct {
	Format        string  `json:"format"`
	Stream        string  `json:"stream"`
	FirstSequence uint64  `json:"first_sequence"`
	PriorHash     string  `json:"prior_hash"`
	Events        []Event `json:"events"`
}

func eventNonce() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func validHex(s string, n int) bool {
	raw, e := hex.DecodeString(s)
	return e == nil && len(raw) == n && hex.EncodeToString(raw) == s
}
func EventHash(e Event) string   { e.Hash = ""; b, _ := json.Marshal(e); return SHA(b) }
func validTrigger(s string) bool { return s == "manual" || s == "lifecycle" || s == "supervisor" }
func validEvent(e Event) bool {
	if e.Sequence == 0 || e.Sequence > MaxSequence || !validHex(e.ID, 16) || !validHex(e.Attempt, 16) || !validHex(e.ConfigSHA, 32) || !validHex(e.PreviousHash, 32) || !validHex(e.Hash, 32) || e.Hash != EventHash(e) || e.At.IsZero() || e.ActiveBans < 0 || e.ActiveBans > MaxEntries || !validTrigger(e.Trigger) {
		return false
	}
	switch e.Kind {
	case "repair_started", "repair_completed":
		return e.ErrorCode == ""
	case "repair_interrupted":
		return e.ErrorCode == "process_interrupted"
	case "repair_failed":
		switch e.ErrorCode {
		case "invalid_configuration", "invalid_state", "foreign_firewall", "kernel_unavailable", "agent_busy", "unsupported_platform", "agent_event_journal_failed":
			return true
		}
	}
	return false
}

func (j eventJournal) validate() error {
	if j.Format != EventFormat || !validHex(j.Stream, 16) || j.FirstSequence == 0 || len(j.Events) == 0 || len(j.Events) > JournalLimit || !validHex(j.PriorHash, 32) {
		return ErrJournal
	}
	prior := j.PriorHash
	seen := map[string]bool{}
	for i, event := range j.Events {
		if !validEvent(event) || event.Sequence != j.FirstSequence+uint64(i) || event.PreviousHash != prior || seen[event.ID] {
			return ErrJournal
		}
		seen[event.ID] = true
		prior = event.Hash
	}
	return nil
}

func readJournal(dir string) (eventJournal, bool, error) {
	data, e := regularRead(filepath.Join(dir, "agent-events.json"), MaxJournalBytes)
	if errors.Is(e, os.ErrNotExist) {
		return eventJournal{}, true, nil
	}
	if e != nil || validateJSON(data) != nil {
		return eventJournal{}, false, ErrJournal
	}
	var j eventJournal
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || j.validate() != nil {
		return j, false, ErrJournal
	}
	return j, false, nil
}

func writeJournal(dir string, j eventJournal) error {
	data, e := json.Marshal(j)
	if e != nil || len(data) > MaxJournalBytes {
		return ErrJournal
	}
	f, e := os.CreateTemp(dir, ".agent-events-*")
	if e != nil {
		return ErrJournal
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return ErrJournal
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return ErrJournal
	}
	if e = f.Close(); e != nil {
		return ErrJournal
	}
	if e = os.Rename(name, filepath.Join(dir, "agent-events.json")); e != nil {
		return ErrJournal
	}
	if e = syncDirectory(dir); e != nil {
		return ErrJournal
	}
	return nil
}

func appendEvent(dir string, e Event) (Event, error) {
	unlock, err := stateLock(filepath.Join(dir, "agent-events.lock"))
	if err != nil {
		return e, ErrJournal
	}
	defer unlock()
	j, missing, err := readJournal(dir)
	if err != nil {
		return e, err
	}
	if missing {
		stream, err := eventNonce()
		if err != nil {
			return e, ErrJournal
		}
		j = eventJournal{Format: EventFormat, Stream: stream, FirstSequence: 1, PriorHash: SHA(nil), Events: []Event{}}
	}
	e.Sequence = j.FirstSequence + uint64(len(j.Events))
	if e.Sequence > MaxSequence {
		return e, ErrJournal
	}
	e.PreviousHash = j.PriorHash
	if len(j.Events) > 0 {
		e.PreviousHash = j.Events[len(j.Events)-1].Hash
	}
	e.ID, err = eventNonce()
	if err != nil {
		return e, ErrJournal
	}
	e.At = time.Now().UTC()
	e.Hash = EventHash(e)
	if !validEvent(e) {
		return e, ErrJournal
	}
	j.Events = append(j.Events, e)
	if len(j.Events) > JournalLimit {
		j.PriorHash = j.Events[0].Hash
		j.Events = j.Events[1:]
		j.FirstSequence++
	}
	if err = writeJournal(dir, j); err != nil {
		return e, err
	}
	return e, nil
}

func beginRepairEvent(dir, config, trigger string, count int) (Event, error) {
	if !validTrigger(trigger) {
		return Event{}, ErrJournal
	}
	j, missing, e := readJournal(dir)
	if e != nil {
		return Event{}, e
	}
	if !missing && len(j.Events) > 0 {
		last := j.Events[len(j.Events)-1]
		if last.Kind == "repair_started" {
			last.Kind = "repair_interrupted"
			last.ErrorCode = "process_interrupted"
			if _, e = appendEvent(dir, last); e != nil {
				return Event{}, e
			}
		}
	}
	attempt, e := eventNonce()
	if e != nil {
		return Event{}, ErrJournal
	}
	return appendEvent(dir, Event{Attempt: attempt, Kind: "repair_started", Trigger: trigger, ConfigSHA: config, ActiveBans: count})
}

// Reading does not initialize or acknowledge a remote journal. Lost responses
// can safely request the same bounded page again without deleting host events.
func ReadEvents(dir string, requested EventCursor, limit int) (EventSnapshot, error) {
	s := EventSnapshot{Format: EventFormat, Requested: requested, Events: []Event{}}
	if validateDirectory(dir) != nil || limit < 1 || limit > EventBatchLimit || !ValidCursor(requested) {
		return s, ErrJournal
	}
	j, missing, e := readJournal(dir)
	if e != nil {
		return s, e
	}
	if missing {
		s.Missing = true
		return s, nil
	}
	s.Stream = j.Stream
	s.FirstSequence = j.FirstSequence
	s.LastSequence = j.FirstSequence + uint64(len(j.Events)) - 1
	start := 0
	if requested.Stream == j.Stream {
		for start < len(j.Events) && j.Events[start].Sequence <= requested.Sequence {
			start++
		}
	}
	s.AnchorHash = j.PriorHash
	if start > 0 {
		s.AnchorHash = j.Events[start-1].Hash
	}
	end := min(len(j.Events), start+limit)
	s.Events = append(s.Events, j.Events[start:end]...)
	s.More = end < len(j.Events)
	return s, nil
}

func DecodeEventSnapshot(raw []byte) (EventSnapshot, error) {
	var s EventSnapshot
	if len(raw) > 60<<10 || validateJSON(raw) != nil {
		return s, ErrJournal
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || s.Format != EventFormat || len(s.Events) > EventBatchLimit || !ValidCursor(s.Requested) {
		return s, ErrJournal
	}
	if s.Missing {
		if s.Stream != "" || len(s.Events) != 0 || s.FirstSequence != 0 || s.LastSequence != 0 || s.AnchorHash != "" || s.More {
			return s, ErrJournal
		}
		return s, nil
	}
	if !validHex(s.Stream, 16) || !validHex(s.AnchorHash, 32) || s.FirstSequence == 0 || s.LastSequence < s.FirstSequence || s.LastSequence > MaxSequence {
		return s, ErrJournal
	}
	if len(s.Events) > 0 {
		expected := s.FirstSequence
		if s.Requested.Stream == s.Stream {
			expected = max(expected, s.Requested.Sequence+1)
		}
		if s.Events[0].Sequence != expected {
			return s, ErrJournal
		}
	} else if s.Requested.Stream != s.Stream || s.Requested.Sequence < s.LastSequence {
		return s, ErrJournal
	}
	prior := s.AnchorHash
	seen := map[string]bool{}
	for i, e := range s.Events {
		if !validEvent(e) || e.PreviousHash != prior || seen[e.ID] || e.Sequence < s.FirstSequence || e.Sequence > s.LastSequence || i > 0 && e.Sequence != s.Events[i-1].Sequence+1 {
			return s, ErrJournal
		}
		seen[e.ID] = true
		prior = e.Hash
	}
	if len(s.Events) > 0 && s.More != (s.Events[len(s.Events)-1].Sequence < s.LastSequence) {
		return s, ErrJournal
	}
	if len(s.Events) == 0 && s.More {
		return s, ErrJournal
	}
	return s, nil
}

func ValidCursor(c EventCursor) bool {
	if c.Stream == "" {
		return c.Sequence == 0 && c.Hash == ""
	}
	return validHex(c.Stream, 16) && c.Sequence > 0 && c.Sequence <= MaxSequence && validHex(c.Hash, 32)
}
