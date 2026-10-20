package notifications

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
)

func cloneSettings(s Settings) Settings {
	s.SMS.NativeSMS.Verification.Parameters = slices.Clone(s.SMS.NativeSMS.Verification.Parameters)
	s.SMS.NativeSMS.Notification.Parameters = slices.Clone(s.SMS.NativeSMS.Notification.Parameters)
	s.Webhook.NativeSMS.Verification.Parameters = slices.Clone(s.Webhook.NativeSMS.Verification.Parameters)
	s.Webhook.NativeSMS.Notification.Parameters = slices.Clone(s.Webhook.NativeSMS.Notification.Parameters)
	return s
}
func publicSettings(c config) Settings {
	out := cloneSettings(c.Settings)
	out.SMTP.PasswordConfigured = c.SMTPPassword != ""
	out.Webhook.BearerConfigured = c.WebhookBearer != ""
	out.Webhook.SecretConfigured = c.WebhookSecret != ""
	out.SMS.BearerConfigured = c.SMSBearer != ""
	out.SMS.SecretConfigured = c.SMSSecret != ""
	return out
}
func (s *Service) Settings(ctx context.Context, id string) (Settings, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Settings{}, e
	}
	if !p.CanManage {
		return Settings{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return publicSettings(s.data.Config), nil
}
func (s *Service) SaveSettings(ctx context.Context, id string, in SettingsInput) (Settings, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Settings{}, e
	}
	if !p.CanManage {
		return Settings{}, ErrDenied
	}
	if in.RequestID != "" && !idPattern.MatchString(in.RequestID) {
		return Settings{}, ErrInvalid
	}
	raw, e := json.Marshal(in)
	if e != nil {
		return Settings{}, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	var out Settings
	e = s.mutate(func(d *state) error {
		if in.RequestID != "" {
			for _, r := range d.SettingsReceipts {
				if r.ActorID == id && r.RequestID == in.RequestID {
					if r.Hash != hash {
						return ErrConflict
					}
					out = cloneSettings(r.Result)
					return nil
				}
			}
			if len(d.SettingsReceipts) >= 2000 {
				return ErrCapacity
			}
		}
		if d.Config.Revision != in.Revision {
			return ErrConflict
		}
		next := d.Config
		next.Settings = cloneSettings(Settings{Revision: in.Revision + 1, SMTP: in.SMTP, Webhook: in.Webhook, SMS: in.SMS})
		if d.Config.Webhook.Provider != in.Webhook.Provider {
			next.WebhookBearer = ""
			next.WebhookSecret = ""
		}
		if d.Config.SMS.Provider != in.SMS.Provider {
			next.SMSBearer = ""
			next.SMSSecret = ""
		}
		for _, pair := range []struct {
			input  *string
			value  *string
			header bool
		}{{in.SMTPPassword, &next.SMTPPassword, false}, {in.WebhookBearer, &next.WebhookBearer, true}, {in.WebhookSecret, &next.WebhookSecret, false}, {in.SMSBearer, &next.SMSBearer, true}, {in.SMSSecret, &next.SMSSecret, false}} {
			if pair.input == nil {
				continue
			}
			v := *pair.input
			if len(v) > 4096 || strings.ContainsRune(v, 0) || pair.header && !validText(v, 4096) {
				return ErrInvalid
			}
			*pair.value = v
		}
		if next.Validate() != nil || next.SMTP.Enabled && next.SMTP.Username == "" && next.SMTPPassword != "" {
			return ErrInvalid
		}
		d.Config = next
		out = publicSettings(next)
		if in.RequestID != "" {
			d.SettingsReceipts = append(d.SettingsReceipts, settingsReceipt{ActorID: id, RequestID: in.RequestID, Hash: hash, Result: cloneSettings(out)})
		}
		audit(d, Audit{At: s.now().UTC(), Actor: p.Actor, Action: "settings_saved"})
		return nil
	})
	return out, e
}
func publicProfile(p profile) Preferences {
	out := p.Preferences
	out.Topics = cloneTopics(p.Topics)
	out.EmailChallengeExpires = p.EmailCode.Expires
	out.PhoneChallengeExpires = p.PhoneCode.Expires
	return out
}
func (s *Service) Preferences(ctx context.Context, id string) (Preferences, error) {
	if _, e := s.principal(ctx, id); e != nil {
		return Preferences{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return publicProfile(profileFor(s.data, id)), nil
}
func (s *Service) SavePreferences(ctx context.Context, id string, in PreferencesInput) (Preferences, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Preferences{}, e
	}
	if in.Validate() != nil {
		return Preferences{}, ErrInvalid
	}
	var out Preferences
	e = s.mutate(func(d *state) error {
		v := profileFor(*d, id)
		if in.Revision != v.Revision {
			return ErrConflict
		}
		if v.Email != in.Email {
			v.EmailVerified = false
			v.EmailCode = challenge{}
		}
		if v.Phone != in.Phone {
			v.PhoneVerified = false
			v.PhoneCode = challenge{}
		}
		for _, rows := range in.Topics {
			if slices.Contains(rows, "email") && (!v.EmailVerified || in.Email == "") || slices.Contains(rows, "sms") && (!v.PhoneVerified || in.Phone == "") {
				return ErrVerification
			}
		}
		v.Email, v.Phone, v.Language = in.Email, in.Phone, in.Language
		v.Topics = cloneTopics(in.Topics)
		v.Revision++
		d.Profiles[id] = v
		out = publicProfile(v)
		audit(d, Audit{At: s.now().UTC(), Actor: p.Actor, Action: "preferences_saved", UserID: id})
		return nil
	})
	return out, e
}
func (s *Service) DetectLanguage(ctx context.Context, id, locale string) error {
	if _, e := s.principal(ctx, id); e != nil {
		return e
	}
	if locale != "en" && locale != "zh-CN" {
		return ErrInvalid
	}
	return s.mutate(func(d *state) error {
		v := profileFor(*d, id)
		if v.DetectedLanguage == locale {
			return nil
		}
		v.DetectedLanguage = locale
		d.Profiles[id] = v
		return nil
	})
}
func challengeDigest(id, channel, address, nonce, code string) string {
	return eventfeed.Digest([]string{id, channel, address, nonce, code})
}
func recent(rows []time.Time, after time.Time) []time.Time {
	out := []time.Time{}
	for _, v := range rows {
		if v.After(after) {
			out = append(out, v)
		}
	}
	return out
}
func (s *Service) RequestVerification(ctx context.Context, id, channel string) (Preferences, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Preferences{}, e
	}
	if channel != "email" && channel != "sms" {
		return Preferences{}, ErrInvalid
	}
	number, e := rand.Int(rand.Reader, big.NewInt(1000000))
	if e != nil {
		return Preferences{}, e
	}
	code := fmt.Sprintf("%06d", number.Int64())
	nonce, e := newID("verify-")
	if e != nil {
		return Preferences{}, e
	}
	var out Preferences
	e = s.mutate(func(d *state) error {
		v := profileFor(*d, id)
		now := s.now().UTC()
		v.Requests = recent(v.Requests, now.Add(-time.Hour))
		if len(v.Requests) >= 6 {
			return ErrRateLimit
		}
		address := v.Email
		c := &v.EmailCode
		enabled := d.Config.SMTP.Enabled
		if channel == "sms" {
			address = v.Phone
			c = &v.PhoneCode
			enabled = d.Config.SMS.Enabled
		}
		if address == "" || !enabled {
			return ErrInvalid
		}
		if !c.Expires.IsZero() && c.Expires.After(now.Add(9*time.Minute)) {
			return ErrRateLimit
		}
		if len(d.Deliveries) >= MaxDeliveries {
			return ErrCapacity
		}
		*c = challenge{Hash: challengeDigest(id, channel, address, nonce, code), Nonce: nonce, Expires: now.Add(10 * time.Minute)}
		v.Requests = append(v.Requests, now)
		v.Revision++
		d.Profiles[id] = v
		mid := "verification-" + eventfeed.Digest([]string{id, nonce, channel})
		did := deliveryID(mid, channel)
		m := Message{ID: mid, UserID: id, Topic: "system", Source: Source{Kind: "verification", ID: id, EventID: eventfeed.Digest(nonce), Action: channel}, At: now, Link: "/console/notifications", State: "verification"}
		d.Deliveries[did] = delivery{Delivery: Delivery{ID: did, MessageID: mid, UserID: id, Channel: channel, State: "queued", Revision: 1, ConfigRevision: d.Config.Revision, CreatedAt: now, UpdatedAt: now}, Address: address, Code: code, ChallengeHash: c.Hash, Message: m}
		out = publicProfile(v)
		audit(d, Audit{At: now, Actor: p.Actor, Action: "verification_requested", UserID: id, DeliveryID: did})
		return nil
	})
	return out, e
}
func (s *Service) Verify(ctx context.Context, id, channel, code string) (Preferences, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Preferences{}, e
	}
	if channel != "email" && channel != "sms" || len(code) > 16 {
		return Preferences{}, ErrInvalid
	}
	var out Preferences
	accepted := false
	e = s.mutate(func(d *state) error {
		v := profileFor(*d, id)
		c := &v.EmailCode
		address := v.Email
		if channel == "sms" {
			c = &v.PhoneCode
			address = v.Phone
		}
		if c.Hash == "" || !s.now().Before(c.Expires) || c.Attempts >= 8 {
			return ErrVerification
		}
		c.Attempts++
		actual := challengeDigest(id, channel, address, c.Nonce, code)
		if len(code) == 6 && subtle.ConstantTimeCompare([]byte(actual), []byte(c.Hash)) == 1 {
			accepted = true
			*c = challenge{}
			if channel == "email" {
				v.EmailVerified = true
			} else {
				v.PhoneVerified = true
			}
			v.Revision++
			audit(d, Audit{At: s.now().UTC(), Actor: p.Actor, Action: "contact_verified", UserID: id})
		}
		d.Profiles[id] = v
		out = publicProfile(v)
		return nil
	})
	if e != nil {
		return Preferences{}, e
	}
	if !accepted {
		return out, ErrVerification
	}
	return out, nil
}
