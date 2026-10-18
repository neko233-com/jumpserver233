// Package reporting aggregates authorized metadata. Raw commands, credentials,
// result bodies, paths, user names and host names do not enter its report model.
package reporting

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"time"
)

var ErrInvalid = errors.New("invalid report request")
var ErrLimit = errors.New("report source limit reached")
var ErrDenied = errors.New("report denied")

const MaxEntries = 100000
const MaxSources = 20

var code = regexp.MustCompile("^[a-z][a-z0-9_]{0,47}$")

// Entry contains only metadata already filtered by the source's live authority.
type Entry struct {
	At    time.Time
	State string
}
type Query struct {
	From            time.Time `json:"from"`
	To              time.Time `json:"to"`
	IncludePlatform bool      `json:"include_platform"`
	Sources         []string  `json:"sources"`
}
type Source struct {
	ID, Scope, Mode string
	Read            func(context.Context, func(Entry) error) error
	Status          string
}
type Count struct {
	State string `json:"state"`
	Count int    `json:"count"`
}
type Day struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}
type Stats struct {
	ID         string    `json:"id"`
	Scope      string    `json:"scope"`
	Mode       string    `json:"mode"`
	Status     string    `json:"status"`
	CapturedAt time.Time `json:"captured_at"`
	Retained   *int      `json:"retained,omitempty"`
	Matched    *int      `json:"matched,omitempty"`
	Oldest     time.Time `json:"oldest,omitzero"`
	Newest     time.Time `json:"newest,omitzero"`
	States     []Count   `json:"states"`
	Days       []Day     `json:"days"`
}
type Report struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Query       Query     `json:"query"`
	Partial     bool      `json:"partial"`
	Sources     []Stats   `json:"sources"`
}

func Validate(q Query, now time.Time) error {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > 366*24*time.Hour || q.To.After(now.Add(time.Minute)) || len(q.Sources) > MaxSources {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range q.Sources {
		if !code.MatchString(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func Build(ctx context.Context, q Query, sources []Source, now time.Time) (Report, error) {
	out := Report{Version: 1, GeneratedAt: now.UTC(), Query: q, Sources: []Stats{}}
	if e := Validate(q, now); e != nil {
		return out, e
	}
	if len(sources) > MaxSources {
		return out, ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if !code.MatchString(s.ID) || seen[s.ID] || !slices.Contains([]string{"mine", "visible", "all", "platform_mine", "platform_all"}, s.Scope) || !slices.Contains([]string{"inventory", "history"}, s.Mode) {
			return out, ErrInvalid
		}
		seen[s.ID] = true
	}
	for _, id := range q.Sources {
		if !seen[id] {
			return out, ErrInvalid
		}
	}
	for _, s := range sources {
		if len(q.Sources) > 0 && !slices.Contains(q.Sources, s.ID) {
			continue
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		row := Stats{ID: s.ID, Scope: s.Scope, Mode: s.Mode, Status: s.Status, CapturedAt: time.Now().UTC(), States: []Count{}, Days: []Day{}}
		if row.Status != "" {
			if !slices.Contains([]string{"denied", "unavailable"}, row.Status) {
				return out, ErrInvalid
			}
			if row.Status == "unavailable" {
				out.Partial = true
			}
			out.Sources = append(out.Sources, row)
			continue
		}
		if s.Read == nil {
			return out, ErrInvalid
		}
		retained, matched := 0, 0
		states := map[string]int{}
		firstDay := q.From.UTC().Truncate(24 * time.Hour)
		if s.Mode == "history" {
			for d := firstDay; d.Before(q.To); d = d.AddDate(0, 0, 1) {
				key := d.Format(time.DateOnly)
				row.Days = append(row.Days, Day{Date: key})
			}
		}
		e := s.Read(ctx, func(v Entry) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retained >= MaxEntries {
				return ErrLimit
			}
			if !code.MatchString(v.State) || (s.Mode == "history" && v.At.IsZero()) {
				return ErrInvalid
			}
			retained++
			if !v.At.IsZero() {
				if row.Oldest.IsZero() || v.At.Before(row.Oldest) {
					row.Oldest = v.At.UTC()
				}
				if v.At.After(row.Newest) {
					row.Newest = v.At.UTC()
				}
			}
			if s.Mode == "history" && (v.At.Before(q.From) || !v.At.Before(q.To)) {
				return nil
			}
			if len(states) >= 64 && states[v.State] == 0 {
				return ErrLimit
			}
			matched++
			states[v.State]++
			if s.Mode == "history" {
				day := int(v.At.UTC().Truncate(24*time.Hour).Sub(firstDay) / (24 * time.Hour))
				row.Days[day].Count++
			}
			return nil
		})
		row.CapturedAt = time.Now().UTC()
		if e != nil && (!errors.Is(e, ErrLimit) || retained == 0) {
			row.Status = "unavailable"
			if errors.Is(e, ErrLimit) {
				row.Status = "limited"
			}
			row.Oldest = time.Time{}
			row.Newest = time.Time{}
			row.Days = []Day{}
			out.Partial = true
		} else {
			row.Status = "ok"
			if errors.Is(e, ErrLimit) {
				row.Status = "limited"
				out.Partial = true
			}
			row.Retained = &retained
			row.Matched = &matched
			keys := make([]string, 0, len(states))
			for k := range states {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				row.States = append(row.States, Count{k, states[k]})
			}
		}
		out.Sources = append(out.Sources, row)
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

// CSV repeats scope, capture status and interval on every row, including empty
// sources. Failed sources have blank counts rather than invented zeros.
func CSV(w io.Writer, r Report) error {
	// Validate finite identifiers before serializing even a caller-built report.
	for _, s := range r.Sources {
		if !code.MatchString(s.ID) || !code.MatchString(s.Scope) || !code.MatchString(s.Mode) || !code.MatchString(s.Status) {
			return ErrInvalid
		}
		for _, v := range s.States {
			if !code.MatchString(v.State) || v.Count < 0 {
				return ErrInvalid
			}
		}
		for _, v := range s.Days {
			if _, e := time.Parse(time.DateOnly, v.Date); e != nil || v.Count < 0 {
				return ErrInvalid
			}
		}
	}
	c := csv.NewWriter(w)
	if e := c.Write([]string{"version", "generated_at", "from_inclusive", "to_exclusive", "source", "scope", "mode", "status", "captured_at", "retained_records", "matched_records", "oldest_observed", "newest_observed", "row_kind", "state", "date_utc", "count"}); e != nil {
		return e
	}
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	number := func(v *int) string {
		if v == nil {
			return ""
		}
		return strconv.Itoa(*v)
	}
	for _, s := range r.Sources {
		base := []string{strconv.Itoa(r.Version), stamp(r.GeneratedAt), stamp(r.Query.From), stamp(r.Query.To), s.ID, s.Scope, s.Mode, s.Status, stamp(s.CapturedAt), number(s.Retained), number(s.Matched), stamp(s.Oldest), stamp(s.Newest)}
		if e := c.Write(append(slices.Clone(base), "summary", "", "", "")); e != nil {
			return e
		}
		for _, v := range s.States {
			if e := c.Write(append(slices.Clone(base), "state", v.State, "", strconv.Itoa(v.Count))); e != nil {
				return e
			}
		}
		for _, v := range s.Days {
			if e := c.Write(append(slices.Clone(base), "day", "", v.Date, strconv.Itoa(v.Count))); e != nil {
				return e
			}
		}
	}
	c.Flush()
	return c.Error()
}
