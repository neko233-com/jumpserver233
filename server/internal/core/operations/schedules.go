package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/robfig/cron/v3"
)

// Schedule is a command plan's calendar configuration. All persisted instants
// are UTC; Timezone applies only to the five-field cron expression.
type Schedule struct {
	Kind            string    `json:"kind"`
	RunAt           time.Time `json:"run_at,omitzero"`
	IntervalSeconds int       `json:"interval_seconds,omitempty"`
	CronExpression  string    `json:"cron_expression,omitempty"`
	Timezone        string    `json:"timezone,omitempty"`
	EndAt           time.Time `json:"end_at,omitzero"`
	MisfirePolicy   string    `json:"misfire_policy,omitempty"`
	GraceSeconds    int       `json:"grace_seconds,omitempty"`
	FoldPolicy      string    `json:"fold_policy,omitempty"`
}
type ScheduleUpdate struct {
	Revision int `json:"revision"`
	Schedule
}
type PreviewInput struct {
	Schedule
	After time.Time `json:"after,omitzero"`
	Limit int       `json:"limit,omitempty"`
}
type Occurrence struct {
	At    time.Time `json:"at"`
	Local string    `json:"local"`
}
type SchedulePreview struct {
	Schedule
	After       time.Time    `json:"after"`
	Occurrences []Occurrence `json:"occurrences"`
}
type ScheduleActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type ScheduleEvent struct {
	ID       string        `json:"id"`
	PlanID   string        `json:"plan_id"`
	At       time.Time     `json:"at"`
	Actor    ScheduleActor `json:"actor"`
	Action   string        `json:"action"`
	Revision int           `json:"revision"`
	Before   Schedule      `json:"before"`
	After    Schedule      `json:"after"`
}

var errScheduleEnded = errors.New("schedule has no remaining occurrence")
var cronField = regexp.MustCompile("^[A-Za-z0-9*/,\\-]+$")
var calendarParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func scheduleOf(in PlanInput) Schedule {
	return Schedule{in.Kind, in.RunAt, in.IntervalSeconds, in.CronExpression, in.Timezone, in.EndAt, in.MisfirePolicy, in.GraceSeconds, in.FoldPolicy}
}
func applySchedule(in *PlanInput, c Schedule) {
	in.Kind, in.RunAt, in.IntervalSeconds = c.Kind, c.RunAt, c.IntervalSeconds
	in.CronExpression, in.Timezone, in.EndAt = c.CronExpression, c.Timezone, c.EndAt
	in.MisfirePolicy, in.GraceSeconds, in.FoldPolicy = c.MisfirePolicy, c.GraceSeconds, c.FoldPolicy
}
func parseCalendar(c Schedule) (*cron.SpecSchedule, error) {
	fields := strings.Fields(c.CronExpression)
	if len(c.CronExpression) > 128 || len(fields) != 5 || c.Timezone == "" || len(c.Timezone) > 64 || c.Timezone == "Local" || strings.ContainsAny(c.Timezone, "\\\x00\r\n\t ") {
		return nil, ErrInvalid
	}
	for _, f := range fields {
		if !cronField.MatchString(f) {
			return nil, ErrInvalid
		}
	}
	loc, e := time.LoadLocation(c.Timezone)
	if e != nil {
		return nil, ErrInvalid
	}
	parsed, e := calendarParser.Parse(strings.Join(fields, " "))
	if e != nil {
		return nil, ErrInvalid
	}
	spec, ok := parsed.(*cron.SpecSchedule)
	if !ok {
		return nil, ErrInvalid
	}
	spec.Location = loc
	return spec, nil
}
func normalizeSchedule(c Schedule, now time.Time, persisted bool) (Schedule, error) {
	if !c.RunAt.IsZero() {
		c.RunAt = c.RunAt.UTC()
	}
	if !c.EndAt.IsZero() {
		c.EndAt = c.EndAt.UTC()
	}
	if !c.EndAt.IsZero() && !c.RunAt.IsZero() && !c.EndAt.After(c.RunAt) || !persisted && (!c.RunAt.IsZero() && (!c.RunAt.After(now) || c.RunAt.After(now.AddDate(10, 0, 0))) || !c.EndAt.IsZero() && !c.EndAt.After(now)) {
		return c, ErrInvalid
	}
	if c.Kind != "cron" && (c.CronExpression != "" || c.Timezone != "" || c.MisfirePolicy != "" || c.GraceSeconds != 0 || c.FoldPolicy != "") {
		return c, ErrInvalid
	}
	switch c.Kind {
	case "batch":
		if !c.RunAt.IsZero() || c.IntervalSeconds != 0 || !c.EndAt.IsZero() {
			return c, ErrInvalid
		}
	case "once":
		if c.RunAt.IsZero() || c.IntervalSeconds != 0 || !c.EndAt.IsZero() {
			return c, ErrInvalid
		}
	case "interval":
		if c.IntervalSeconds < 60 || c.IntervalSeconds > 31*86400 {
			return c, ErrInvalid
		}
	case "cron":
		if c.IntervalSeconds != 0 {
			return c, ErrInvalid
		}
		if strings.ContainsAny(c.CronExpression, "\x00\r\n") {
			return c, ErrInvalid
		}
		c.CronExpression = strings.Join(strings.Fields(c.CronExpression), " ")
		if c.MisfirePolicy == "" {
			c.MisfirePolicy = "coalesce"
		}
		if c.GraceSeconds == 0 {
			c.GraceSeconds = 60
		}
		if c.FoldPolicy == "" {
			c.FoldPolicy = "once"
		}
		if !slices.Contains([]string{"skip", "coalesce"}, c.MisfirePolicy) || c.GraceSeconds < 1 || c.GraceSeconds > 3600 || !slices.Contains([]string{"once", "both"}, c.FoldPolicy) {
			return c, ErrInvalid
		}
		if _, e := parseCalendar(c); e != nil {
			return c, e
		}
	default:
		return c, ErrInvalid
	}
	if !persisted {
		if _, e := firstOccurrence(c, now); e != nil {
			return c, ErrInvalid
		}
	}
	return c, nil
}
func wallSlot(t time.Time, loc *time.Location) string { return t.In(loc).Format("2006-01-02T15:04") }
func nextCalendar(c Schedule, after time.Time, watermark string) (time.Time, error) {
	spec, e := parseCalendar(c)
	if e != nil {
		return time.Time{}, e
	}
	if !c.RunAt.IsZero() && after.Before(c.RunAt) {
		after = c.RunAt.Add(-time.Nanosecond)
	}
	horizon := after.AddDate(10, 0, 0)
	// A repeated civil day in historic IANA zones can contain 1,440 minutes.
	// Keep the search bounded while suppressing already handled wall-clock slots.
	for range 2000 {
		next := spec.Next(after)
		if next.IsZero() {
			next = spec.Next(after.AddDate(5, 0, 0))
		}
		if next.IsZero() || next.After(horizon) || !c.EndAt.IsZero() && !next.Before(c.EndAt) {
			return time.Time{}, errScheduleEnded
		}
		if c.FoldPolicy == "both" || watermark == "" || wallSlot(next, spec.Location) > watermark {
			return next.UTC(), nil
		}
		after = next
	}
	return time.Time{}, errScheduleEnded
}
func firstOccurrence(c Schedule, now time.Time) (time.Time, error) {
	var at time.Time
	switch c.Kind {
	case "batch":
		at = now
	case "once":
		at = c.RunAt
	case "interval":
		at = c.RunAt
		if at.IsZero() {
			at = now.Add(time.Duration(c.IntervalSeconds) * time.Second)
		}
	case "cron":
		return nextCalendar(c, now, "")
	default:
		return at, ErrInvalid
	}
	if !c.EndAt.IsZero() && !at.Before(c.EndAt) {
		return time.Time{}, errScheduleEnded
	}
	return at.UTC(), nil
}
func nextPlanOccurrence(p Plan, now time.Time) (time.Time, error) {
	c := scheduleOf(p.PlanInput)
	if p.LastScheduledAt.After(now) {
		now = p.LastScheduledAt
	}
	if c.Kind == "cron" {
		return nextCalendar(c, now, p.CalendarWatermark)
	}
	at := now.Add(time.Duration(p.IntervalSeconds) * time.Second)
	if !p.EndAt.IsZero() && !at.Before(p.EndAt) {
		return time.Time{}, errScheduleEnded
	}
	return at, nil
}
func markOccurrence(p *Plan) {
	at := p.NextRun
	if at.After(p.LastScheduledAt) {
		p.LastScheduledAt = at
	}
	if p.Kind == "cron" {
		if spec, e := parseCalendar(scheduleOf(p.PlanInput)); e == nil {
			p.CalendarWatermark = max(p.CalendarWatermark, wallSlot(at, spec.Location))
		}
	}
}

// CanonicalSchedule validates shape and UTC/default fields independently of
// whether a schedule still has future occurrences.
func CanonicalSchedule(c Schedule) (Schedule, error) { return normalizeSchedule(c, time.Time{}, true) }

// AdvanceSchedule shares command-plan misfire/DST watermark semantics with
// other native schedulers. An exhausted schedule returns a zero next instant.
func AdvanceSchedule(c Schedule, now, scheduled time.Time, watermark string) (time.Time, string, error) {
	c, e := normalizeSchedule(c, now, true)
	if e != nil {
		return time.Time{}, watermark, e
	}
	if c.Kind == "once" {
		return time.Time{}, watermark, nil
	}
	if c.Kind != "interval" && c.Kind != "cron" {
		return time.Time{}, watermark, ErrInvalid
	}
	p := Plan{NextRun: scheduled, CalendarWatermark: watermark}
	applySchedule(&p.PlanInput, c)
	markOccurrence(&p)
	at, e := nextPlanOccurrence(p, now)
	if errors.Is(e, errScheduleEnded) {
		return time.Time{}, p.CalendarWatermark, nil
	}
	return at, p.CalendarWatermark, e
}
func PreviewSchedule(in PreviewInput, now time.Time) (SchedulePreview, error) {
	c, e := normalizeSchedule(in.Schedule, now, true)
	if e != nil {
		return SchedulePreview{}, e
	}
	after := in.After
	if after.IsZero() {
		after = now
	}
	after = after.UTC()
	if after.Year() < 1 || after.Year() > 9980 || in.Limit < 0 || in.Limit > 10 {
		return SchedulePreview{}, ErrInvalid
	}
	limit := in.Limit
	if limit == 0 {
		limit = 5
	}
	out := SchedulePreview{Schedule: c, After: after, Occurrences: []Occurrence{}}
	loc := time.UTC
	if c.Kind == "cron" {
		spec, _ := parseCalendar(c)
		loc = spec.Location
	}
	wall := ""
	for range limit {
		var at time.Time
		if c.Kind == "cron" {
			at, e = nextCalendar(c, after, wall)
		} else if c.Kind == "batch" {
			at = after
		} else if c.Kind == "once" {
			at = c.RunAt
			if !at.After(after) {
				break
			}
		} else {
			at = after.Add(time.Duration(c.IntervalSeconds) * time.Second)
			if !c.RunAt.IsZero() && c.RunAt.After(after) {
				at = c.RunAt
			}
			if !c.EndAt.IsZero() && !at.Before(c.EndAt) {
				break
			}
		}
		if errors.Is(e, errScheduleEnded) {
			break
		}
		if e != nil {
			return out, e
		}
		out.Occurrences = append(out.Occurrences, Occurrence{at.UTC(), at.In(loc).Format(time.RFC3339)})
		after = at
		wall = max(wall, wallSlot(at, loc))
		if c.Kind == "batch" || c.Kind == "once" {
			break
		}
	}
	if len(out.Occurrences) == 0 {
		return out, ErrInvalid
	}
	return out, nil
}
func creationHash(in PlanInput) string {
	raw, _ := json.Marshal([]any{in, in.Origin})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ReplayPlan recognizes the immutable creation payload even after schedule
// edits, template deletion, or the original start time passing. It never queues
// work and does not consume approvals.
func (s *Service) ReplayPlan(owner string, in PlanInput) (Plan, bool, error) {
	s.mu.Lock()
	var found Plan
	for _, p := range s.data.Plans {
		if p.OwnerID == owner && p.RequestID == in.RequestID {
			found = p
			break
		}
	}
	s.mu.Unlock()
	if found.ID == "" {
		return Plan{}, false, nil
	}
	if found.HostPlugin != nil || found.Discovery != nil {
		return Plan{}, true, ErrConflict
	}
	in.Name = strings.TrimSpace(in.Name)
	in.AssetIDs = slices.Clone(in.AssetIDs)
	slices.Sort(in.AssetIDs)
	if in.PlaybookID != "" {
		if in.Command != "" || in.TemplateID != "" || in.PlaybookID != found.PlaybookID {
			return Plan{}, true, ErrConflict
		}
		in.Command = found.Command
		if in.PlaybookTimeout == 0 {
			in.PlaybookTimeout = 3600
		}
		var e error
		in.Variables, e = normalizedBindings(in.Variables)
		if e != nil {
			return Plan{}, true, ErrConflict
		}
	}
	if in.TemplateID != "" {
		if in.Command != "" || in.TemplateID != found.TemplateID {
			return Plan{}, true, ErrConflict
		}
		in.Command = found.Command
		in.TimeoutSeconds = found.TimeoutSeconds
		if in.WorkingDirectory != "" && in.WorkingDirectory != found.WorkingDirectory {
			return Plan{}, true, ErrConflict
		}
		in.WorkingDirectory = found.WorkingDirectory
	}
	validated, e := jobs.Validate(jobs.Input{WorkingDirectory: in.WorkingDirectory, AssetID: "replay", Command: in.Command, TimeoutSeconds: in.TimeoutSeconds})
	if e != nil {
		return Plan{}, true, ErrConflict
	}
	in.Command = validated.Command
	in.TimeoutSeconds = validated.TimeoutSeconds
	c, e := normalizeSchedule(scheduleOf(in), s.now().UTC(), true)
	if e != nil {
		return Plan{}, true, ErrConflict
	}
	applySchedule(&in, c)
	if creationHash(in) != found.CreationHash {
		return Plan{}, true, ErrConflict
	}
	found.AssetIDs = slices.Clone(found.AssetIDs)
	return cloneWorkflowPlan(found), true, nil
}
func appendScheduleEvent(next *state, p Plan, before Schedule, action string, actor ScheduleActor, at time.Time) error {
	if actor.ID == "" {
		actor = ScheduleActor{"system", "system"}
	}
	id, e := newID("schedule-event-")
	if e != nil {
		return e
	}
	next.ScheduleEvents = slices.DeleteFunc(next.ScheduleEvents, func(v ScheduleEvent) bool { return v.At.Before(at.AddDate(-1, 0, 0)) })
	if len(next.ScheduleEvents) >= 4000 {
		next.ScheduleEvents = next.ScheduleEvents[len(next.ScheduleEvents)-3999:]
	}
	next.ScheduleEvents = append(next.ScheduleEvents, ScheduleEvent{id, p.ID, at.UTC(), actor, action, p.ConfigRevision, before, scheduleOf(p.PlanInput)})
	return nil
}

func endSchedule(next *state, p *Plan, at time.Time) error {
	p.Enabled = false
	p.NextRun = time.Time{}
	p.ErrorCode = "schedule_ended"
	p.ConfigRevision++
	return appendScheduleEvent(next, *p, scheduleOf(p.PlanInput), "ended", ScheduleActor{}, at)
}
func (s *Service) ScheduleEvents(id string, offset, limit int) ([]ScheduleEvent, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []ScheduleEvent{}
	total := 0
	for i := len(s.data.ScheduleEvents) - 1; i >= 0; i-- {
		v := s.data.ScheduleEvents[i]
		if v.PlanID != id || v.At.Before(s.now().AddDate(-1, 0, 0)) {
			continue
		}
		if total >= offset && len(rows) < limit {
			rows = append(rows, v)
		}
		total++
	}
	return rows, total, nil
}

func (s *Service) PlanPage(owner string, offset, limit int) ([]Plan, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	rows := s.Plans(owner)
	total := len(rows)
	offset = min(offset, total)
	return rows[offset:min(offset+limit, total)], total, nil
}
func (s *Service) UpdateSchedule(id string, in ScheduleUpdate, actor ScheduleActor) (Plan, error) {
	c, e := normalizeSchedule(in.Schedule, s.now().UTC(), true)
	if e != nil {
		return Plan{}, e
	}
	if c.Kind == "batch" || in.Revision < 1 {
		return Plan{}, ErrInvalid
	}
	var out Plan
	e = s.mutate(func(next *state) error {
		p, ok := next.Plans[id]
		if !ok {
			return ErrNotFound
		}
		if p.HostPlugin != nil || p.Discovery != nil || p.Kind == "batch" || p.Kind == "once" && p.LastRunID != "" {
			return ErrConflict
		}
		if p.ConfigRevision != in.Revision {
			return ErrConflict
		}
		before := scheduleOf(p.PlanInput)
		now := s.now().UTC()
		if !c.EndAt.IsZero() && !c.EndAt.After(now) || !c.RunAt.IsZero() && (c.RunAt.After(now.AddDate(10, 0, 0)) || !c.RunAt.After(now) && (c.RunAt != before.RunAt || c.Kind == "once")) {
			return ErrInvalid
		}
		if before == c {
			out = p
			return nil
		}
		if p.CreationHash == "" {
			original := p.PlanInput
			original.Origin = p.AccessOrigin
			p.CreationHash = creationHash(original)
		}
		applySchedule(&p.PlanInput, c)
		p.ConfigRevision++
		p.ErrorCode = ""
		// A new timezone has a different civil clock; UTC deduplication is retained.
		if before.Timezone != c.Timezone {
			p.CalendarWatermark = ""
		}
		at := s.now().UTC()
		if p.LastScheduledAt.After(at) {
			at = p.LastScheduledAt
		}
		if c.RunAt != before.RunAt && !c.RunAt.IsZero() && !c.RunAt.After(p.LastScheduledAt) {
			return ErrInvalid
		}
		if c.Kind == "cron" {
			p.NextRun, e = nextCalendar(c, at, p.CalendarWatermark)
		} else {
			p.NextRun, e = firstOccurrence(c, at)
		}
		if e != nil {
			return ErrInvalid
		}
		next.Plans[id] = p
		out = p
		return appendScheduleEvent(next, p, before, "updated", actor, s.now())
	})
	out.AssetIDs = slices.Clone(out.AssetIDs)
	return cloneWorkflowPlan(out), e
}
func (s *Service) SetEnabledRevision(id string, enabled bool, revision int, actor ScheduleActor) (Plan, error) {
	var out Plan
	e := s.mutate(func(next *state) error {
		p, ok := next.Plans[id]
		if !ok {
			return ErrNotFound
		}
		if p.Kind == "batch" || p.Kind == "once" && p.LastRunID != "" || p.Discovery != nil {
			return ErrConflict
		}
		if revision != 0 && revision != p.ConfigRevision || p.Kind == "cron" && revision < 1 {
			return ErrConflict
		}
		if p.Enabled == enabled {
			out = p
			return nil
		}
		if enabled && !p.EndAt.IsZero() && !p.EndAt.After(s.now()) {
			return ErrConflict
		}
		before := scheduleOf(p.PlanInput)
		p.Enabled = enabled
		p.ErrorCode = ""
		p.ConfigRevision++
		if enabled && !p.NextRun.After(s.now()) {
			if p.Kind == "once" {
				return ErrConflict
			}
			var e error
			p.NextRun, e = nextPlanOccurrence(p, s.now().UTC())
			if e != nil {
				return ErrConflict
			}
		}
		next.Plans[id] = p
		out = p
		action := "paused"
		if enabled {
			action = "resumed"
		}
		return appendScheduleEvent(next, p, before, action, actor, s.now())
	})
	out.AssetIDs = slices.Clone(out.AssetIDs)
	out.HostPlugin = clonePlugin(out.HostPlugin)
	return cloneWorkflowPlan(out), e
}
