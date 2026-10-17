package notifications

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
)

func (s *Service) appendMessage(d *state, m Message) error {
	if _, ok := d.Messages[m.ID]; ok {
		return nil
	}
	if len(d.Messages) >= MaxMessages {
		return ErrCapacity
	}
	p := profileFor(*d, m.UserID)
	channels := p.Topics[m.Topic]
	m.Inbox = slices.Contains(channels, "inbox")
	d.Messages[m.ID] = m
	for _, channel := range channels {
		if channel == "inbox" {
			continue
		}
		if len(d.Deliveries) >= MaxDeliveries {
			return ErrCapacity
		}
		address := p.Email
		if channel == "sms" {
			address = p.Phone
		} else if channel == "webhook" {
			address = d.Config.Webhook.URL
		}
		id := deliveryID(m.ID, channel)
		d.Deliveries[id] = delivery{Delivery: Delivery{ID: id, MessageID: m.ID, UserID: m.UserID, Channel: channel, State: "queued", Revision: 1, ConfigRevision: d.Config.Revision, CreatedAt: s.now().UTC(), UpdatedAt: s.now().UTC()}, Address: address, Message: m}
	}
	return nil
}
func (s *Service) Test(ctx context.Context, id, requestID string) (Message, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Message{}, e
	}
	if !idPattern.MatchString(requestID) {
		return Message{}, ErrInvalid
	}
	src := Source{Kind: "test", ID: requestID, EventID: eventfeed.Digest([]string{id, requestID}), Action: "test"}
	mid := messageID(src, "system", id)
	var out Message
	e = s.mutate(func(d *state) error {
		if prior, ok := d.Messages[mid]; ok {
			out = cloneMessage(prior)
			return nil
		}
		profile := profileFor(*d, id)
		now := s.now().UTC()
		profile.Tests = recent(profile.Tests, now.Add(-time.Hour))
		if len(profile.Tests) >= 10 {
			return ErrRateLimit
		}
		profile.Tests = append(profile.Tests, now)
		d.Profiles[id] = profile
		m := Message{ID: mid, UserID: id, Topic: "system", Source: src, At: now, Link: "/console/notifications", State: "test"}
		if e := s.appendMessage(d, m); e != nil {
			return e
		}
		out = cloneMessage(d.Messages[mid])
		audit(d, Audit{At: now, Actor: p.Actor, Action: "test_requested", UserID: id})
		return nil
	})
	return out, e
}
func (s *Service) syncFeed(ctx context.Context, feed Feed) error {
	if feed.Read == nil || feed.Recipients == nil || !idPattern.MatchString(feed.Name) {
		return ErrInvalid
	}
	s.mu.Lock()
	c := s.data.Cursors[feed.Name]
	since := s.data.CreatedAt
	s.mu.Unlock()
	if cutoff := s.now().Add(-30 * 24 * time.Hour); cutoff.After(since) {
		since = cutoff
	}
	batch, e := feed.Read(ctx, c.Anchor, since, 64)
	if e != nil {
		return e
	}
	if batch.Cursor != "" && !validHash(batch.Cursor) || len(batch.Events) > 64 {
		return ErrInvalid
	}
	pending := []Message{}
	for _, event := range batch.Events {
		if !validHash(event.ID) || !idPattern.MatchString(event.ResourceID) || event.At.IsZero() || !validText(event.Name, 480) || !validText(event.State, 64) {
			return ErrInvalid
		}
		targets, e := feed.Recipients(ctx, event)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, target := range targets {
			if !idPattern.MatchString(target.UserID) || !slices.Contains(Topics, target.Topic) {
				return ErrInvalid
			}
			key := target.UserID + "/" + target.Topic
			if seen[key] {
				continue
			}
			seen[key] = true
			src := Source{Kind: feed.Name, ID: event.ResourceID, EventID: event.ID, Action: event.State, Revision: event.Revision}
			if target.Topic == "approvals" {
				src.Action = "review"
			}
			link := "/console/notifications"
			if feed.Link != nil {
				link = feed.Link(event)
			}
			m := Message{ID: messageID(src, target.Topic, target.UserID), UserID: target.UserID, Topic: target.Topic, Source: src, Name: event.Name, State: event.State, At: event.At, Link: link}
			s.mu.Lock()
			_, alreadyPublished := s.data.Messages[m.ID]
			s.mu.Unlock()
			if alreadyPublished {
				continue
			}
			ok, e := s.allowed(ctx, target.UserID, m)
			if e != nil {
				return e
			}
			if ok {
				pending = append(pending, m)
			}
		}
	}
	if len(pending) == 0 && c.Anchor == batch.Cursor && (!batch.Gap || c.Gap) {
		return nil
	}
	return s.mutate(func(d *state) error {
		current := d.Cursors[feed.Name]
		if current.Anchor != c.Anchor {
			return ErrConflict
		}
		for _, m := range pending {
			if e := s.appendMessage(d, m); e != nil {
				return e
			}
		}
		if batch.Gap && !current.Gap {
			audit(d, Audit{At: s.now().UTC(), Actor: systemActor(), Action: "source_gap", Code: feed.Name})
		}
		if current.Anchor == batch.Cursor && (!batch.Gap || current.Gap) {
			return nil
		}
		d.Cursors[feed.Name] = cursor{Anchor: batch.Cursor, Gap: current.Gap || batch.Gap, At: s.now().UTC()}
		return nil
	})
}
func systemActor() Actor { return Actor{ID: "system-notifications", Name: "Notification service"} }
func (s *Service) deliveryGuard(ctx context.Context, v delivery) (Outbound, string, error) {
	if e := ctx.Err(); e != nil {
		return Outbound{}, "", e
	}
	if _, e := s.principal(ctx, v.UserID); e != nil {
		if errors.Is(e, ErrDenied) {
			return Outbound{}, "permission_changed", nil
		}
		return Outbound{}, "", e
	}
	s.mu.Lock()
	current, ok := s.data.Deliveries[v.ID]
	p := profileFor(s.data, v.UserID)
	cfg := s.data.Config
	closed := s.closed
	s.mu.Unlock()
	if closed || s.ctx.Err() != nil {
		return Outbound{}, "", ErrUnavailable
	}
	if !ok || current.State != "sending" || current.Revision != v.Revision {
		return Outbound{}, "changed", nil
	}
	if cfg.Revision != v.ConfigRevision {
		return Outbound{}, "configuration_changed", nil
	}
	if v.ChallengeHash != "" {
		c := p.EmailCode
		address := p.Email
		if v.Channel == "sms" {
			c = p.PhoneCode
			address = p.Phone
		}
		if c.Hash != v.ChallengeHash || address != v.Address || c.Attempts >= 8 || !s.now().Before(c.Expires) {
			return Outbound{}, "verification_expired", nil
		}
	} else {
		allowed, e := s.allowed(ctx, v.UserID, v.Message)
		if e != nil {
			return Outbound{}, "", e
		}
		if !allowed {
			return Outbound{}, "permission_changed", nil
		}
		if !slices.Contains(p.Topics[v.Message.Topic], v.Channel) {
			return Outbound{}, "unsubscribed", nil
		}
		if v.Channel == "email" && (!p.EmailVerified || p.Email != v.Address) || v.Channel == "sms" && (!p.PhoneVerified || p.Phone != v.Address) {
			return Outbound{}, "contact_changed", nil
		}
	}
	enabled := cfg.SMTP.Enabled
	bearer, secret := "", ""
	if v.Channel == "webhook" {
		enabled = cfg.Webhook.Enabled
		bearer, secret = cfg.WebhookBearer, cfg.WebhookSecret
		if v.Address != cfg.Webhook.URL {
			return Outbound{}, "configuration_changed", nil
		}
	} else if v.Channel == "sms" {
		enabled = cfg.SMS.Enabled
		bearer, secret = cfg.SMSBearer, cfg.SMSSecret
	}
	if !enabled {
		return Outbound{}, "channel_disabled", nil
	}
	language := p.Language
	if language == "auto" {
		language = p.DetectedLanguage
	}
	return Outbound{ID: v.ID, Channel: v.Channel, Destination: v.Address, Language: language, VerificationCode: v.Code, Message: v.Message, Settings: publicSettings(cfg), SMTPPassword: cfg.SMTPPassword, HTTPBearer: bearer, HTTPSecret: secret}, "", nil
}
func (s *Service) dispatch(v delivery) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); delete(s.active, v.ID); s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()
	out, code, e := s.deliveryGuard(ctx, v)
	result := Outcome{State: "suppressed", Code: code}
	if e != nil {
		result = Outcome{State: "retry", Code: "unavailable"}
	} else if code == "configuration_changed" || code == "channel_disabled" {
		result.State = "failed"
	} else if code == "" {
		out.Guard = func() error {
			_, code, e := s.deliveryGuard(ctx, v)
			if e != nil {
				return e
			}
			if code != "" {
				return ErrDenied
			}
			return nil
		}
		out.SiteURL = s.snapshotRunner().SiteURL
		out.OrganizationID = s.snapshotRunner().OrganizationID
		send := s.snapshotRunner().Send
		if send == nil {
			result = Outcome{State: "retry", Code: "unavailable"}
		} else {
			result = send(ctx, out)
		}
	}
	if s.ctx.Err() != nil {
		return
	}
	if !slices.Contains([]string{"sent", "retry", "failed", "uncertain", "suppressed"}, result.State) || !validText(result.Code, 64) || !validText(result.Receipt, 128) {
		result = Outcome{State: "uncertain", Code: "receipt_unavailable"}
	}
	_ = s.mutate(func(d *state) error {
		current, ok := d.Deliveries[v.ID]
		if !ok || current.State != "sending" || current.Revision != v.Revision {
			return ErrConflict
		}
		current.State = result.State
		current.ErrorCode = result.Code
		current.Receipt = result.Receipt
		current.UpdatedAt = s.now().UTC()
		current.Revision++
		if current.State == "retry" {
			if current.Attempts >= 5 {
				current.State = "failed"
				current.ErrorCode = "attempts_exhausted"
			} else {
				current.NextAttempt = s.now().Add(time.Duration(1<<current.Attempts) * 10 * time.Second)
			}
		} else {
			current.NextAttempt = time.Time{}
			current.Code = ""
		}
		d.Deliveries[v.ID] = current
		audit(d, Audit{At: current.UpdatedAt, Actor: systemActor(), Action: current.State, DeliveryID: v.ID, UserID: v.UserID, Code: current.ErrorCode})
		return nil
	})
}
func (s *Service) Tick() {
	if s.ctx.Err() != nil || !s.op.TryLock() {
		return
	}
	defer s.op.Unlock()
	s.mu.Lock()
	maintenanceDue := s.now().Sub(s.lastMaintenance) >= time.Hour
	s.mu.Unlock()
	if maintenanceDue {
		if e := s.maintain(); e == nil {
			s.mu.Lock()
			s.lastMaintenance = s.now()
			s.mu.Unlock()
		}
	}
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	for _, feed := range s.snapshotRunner().Feeds {
		if ctx.Err() != nil {
			return
		}
		e := s.syncFeed(ctx, feed)
		s.mu.Lock()
		if s.sourceErrors == nil {
			s.sourceErrors = map[string]bool{}
		}
		s.sourceErrors[feed.Name] = e != nil
		s.mu.Unlock()
	}
	// A sender that finished without committing its receipt must not be retried.
	s.mu.Lock()
	stranded := false
	for id, v := range s.data.Deliveries {
		if v.State == "sending" && !s.active[id] {
			stranded = true
			break
		}
	}
	s.mu.Unlock()
	if stranded {
		_ = s.mutate(func(d *state) error {
			for id, v := range d.Deliveries {
				if v.State == "sending" && !s.active[id] {
					v.State, v.ErrorCode = "uncertain", "receipt_unavailable"
					v.Revision++
					v.UpdatedAt = s.now().UTC()
					v.Code = ""
					d.Deliveries[id] = v
				}
			}
			return nil
		})
	}
	s.mu.Lock()
	remaining := 4 - len(s.active)
	ids := []string{}
	for id, v := range s.data.Deliveries {
		if !s.active[id] && (v.State == "queued" || v.State == "retry") && (v.NextAttempt.IsZero() || !s.now().Before(v.NextAttempt)) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	if remaining <= 0 {
		return
	}
	sort.Strings(ids)
	for _, id := range ids[:min(remaining, len(ids))] {
		var claimed delivery
		e := s.mutate(func(d *state) error {
			v, ok := d.Deliveries[id]
			if !ok || v.State != "queued" && v.State != "retry" {
				return ErrConflict
			}
			v.State = "sending"
			v.Attempts++
			v.Revision++
			v.UpdatedAt = s.now().UTC()
			d.Deliveries[id] = v
			claimed = v
			return nil
		})
		if e != nil {
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.active[id] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.dispatch(claimed)
	}
}
func (s *Service) maintain() error {
	return s.mutate(func(d *state) error {
		cutoff := s.now().Add(-30 * 24 * time.Hour)
		retained := map[string]bool{}
		for id, v := range d.Deliveries {
			if s.active[id] {
				retained[v.MessageID] = true
			}
		}
		for id, m := range d.Messages {
			if m.At.Before(cutoff) && !retained[id] {
				delete(d.Messages, id)
			}
		}
		for id, v := range d.Deliveries {
			_, parent := d.Messages[v.MessageID]
			if !s.active[id] && (v.CreatedAt.Before(cutoff) || v.ChallengeHash == "" && !parent) {
				delete(d.Deliveries, id)
			}
		}
		d.Audit = slices.DeleteFunc(d.Audit, func(v Audit) bool { return v.At.Before(s.now().Add(-365 * 24 * time.Hour)) })
		return nil
	})
}
func (s *Service) Start(owner context.Context) {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.wg.Add(1)
	stop := context.AfterFunc(owner, s.cancel)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stop()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			s.Tick()
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
}
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		s.mu.Unlock()
		s.op.Lock()
		s.op.Unlock()
		s.wg.Wait()
	})
}
