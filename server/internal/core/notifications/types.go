package notifications

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
)

var (
	ErrInvalid      = errors.New("invalid notification input")
	ErrDenied       = errors.New("notification permission denied")
	ErrNotFound     = errors.New("notification not found")
	ErrConflict     = errors.New("notification revision changed")
	ErrCapacity     = errors.New("notification capacity reached")
	ErrUnavailable  = errors.New("notification service unavailable")
	ErrVerification = errors.New("contact verification failed")
	ErrRateLimit    = errors.New("notification rate limit reached")
)

const (
	MaxMessages   = 20000
	MaxDeliveries = 40000
	MaxAudit      = 20000
	MaxState      = 64 << 20
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
var Topics = []string{"approvals", "tickets", "jobs", "rotation", "security", "system"}
var Channels = []string{"inbox", "email", "webhook", "sms"}

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Principal struct {
	Actor
	CanManage, CanAudit, CanRetry bool
}
type Source struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	EventID  string `json:"event_id"`
	Action   string `json:"action"`
	Revision int    `json:"revision,omitempty"`
}
type Message struct {
	Inbox  bool       `json:"inbox"`
	ID     string     `json:"id"`
	UserID string     `json:"user_id"`
	Topic  string     `json:"topic"`
	Source Source     `json:"source"`
	Name   string     `json:"name"`
	State  string     `json:"state"`
	At     time.Time  `json:"at"`
	ReadAt *time.Time `json:"read_at,omitempty"`
	Link   string     `json:"link"`
	Actor  string     `json:"actor,omitempty"`
}
type Delivery struct {
	CanRetry       bool      `json:"can_retry"`
	ID             string    `json:"id"`
	MessageID      string    `json:"message_id"`
	UserID         string    `json:"user_id"`
	Channel        string    `json:"channel"`
	State          string    `json:"state"`
	Attempts       int       `json:"attempts"`
	Revision       int       `json:"revision"`
	ConfigRevision int       `json:"config_revision"`
	ErrorCode      string    `json:"error_code,omitempty"`
	Receipt        string    `json:"receipt,omitempty"`
	Destination    string    `json:"destination"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	NextAttempt    time.Time `json:"next_attempt,omitzero"`
}
type Audit struct {
	At         time.Time `json:"at"`
	Actor      Actor     `json:"actor"`
	Action     string    `json:"action"`
	DeliveryID string    `json:"delivery_id,omitempty"`
	UserID     string    `json:"user_id,omitempty"`
	Code       string    `json:"code,omitempty"`
}
type Health struct {
	CreatedAt    time.Time `json:"created_at"`
	SourceGaps   []string  `json:"source_gaps"`
	SourceErrors []string  `json:"source_errors"`
	Pending      int       `json:"pending"`
	Uncertain    int       `json:"uncertain"`
	Failed       int       `json:"failed"`
}
type Page[T any] struct {
	Results []T `json:"results"`
	Total   int `json:"total"`
}
type Preferences struct {
	Revision              int                 `json:"revision"`
	Language              string              `json:"language"`
	DetectedLanguage      string              `json:"detected_language"`
	Email                 string              `json:"email"`
	EmailVerified         bool                `json:"email_verified"`
	Phone                 string              `json:"phone"`
	PhoneVerified         bool                `json:"phone_verified"`
	Topics                map[string][]string `json:"topics"`
	EmailChallengeExpires time.Time           `json:"email_challenge_expires,omitzero"`
	PhoneChallengeExpires time.Time           `json:"phone_challenge_expires,omitzero"`
}
type PreferencesInput struct {
	Revision int                 `json:"revision"`
	Language string              `json:"language"`
	Email    string              `json:"email"`
	Phone    string              `json:"phone"`
	Topics   map[string][]string `json:"topics"`
}
type SMTP struct {
	Enabled            bool   `json:"enabled"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Mode               string `json:"mode"`
	Username           string `json:"username"`
	From               string `json:"from"`
	SubjectPrefix      string `json:"subject_prefix"`
	CA                 string `json:"ca"`
	PasswordConfigured bool   `json:"password_configured"`
}
type HTTPChannel struct {
	Enabled          bool   `json:"enabled"`
	URL              string `json:"url"`
	CA               string `json:"ca"`
	BearerConfigured bool   `json:"bearer_configured"`
	SecretConfigured bool   `json:"secret_configured"`
}
type Settings struct {
	Revision int         `json:"revision"`
	SMTP     SMTP        `json:"smtp"`
	Webhook  HTTPChannel `json:"webhook"`
	SMS      HTTPChannel `json:"sms"`
}
type SettingsInput struct {
	Revision      int         `json:"revision"`
	SMTP          SMTP        `json:"smtp"`
	Webhook       HTTPChannel `json:"webhook"`
	SMS           HTTPChannel `json:"sms"`
	SMTPPassword  *string     `json:"smtp_password"`
	WebhookBearer *string     `json:"webhook_bearer"`
	WebhookSecret *string     `json:"webhook_secret"`
	SMSBearer     *string     `json:"sms_bearer"`
	SMSSecret     *string     `json:"sms_secret"`
}
type Recipient struct{ UserID, Topic string }
type Feed struct {
	Name       string
	Read       func(context.Context, string, time.Time, int) (eventfeed.Batch, error)
	Recipients func(context.Context, eventfeed.Event) ([]Recipient, error)
	Allowed    func(context.Context, string, Source) (bool, error)
	Link       func(eventfeed.Event) string
}
type Runner struct {
	SiteURL        string
	OrganizationID string
	Principal      func(context.Context, string) (Principal, error)
	Feeds          []Feed
	Send           func(context.Context, Outbound) Outcome
}
type Outbound struct {
	SiteURL, OrganizationID                              string
	ID, Channel, Destination, Language, VerificationCode string
	Message                                              Message
	Settings                                             Settings
	SMTPPassword, HTTPBearer, HTTPSecret                 string
	Guard                                                func() error
}
type Outcome struct{ State, Code, Receipt string }

func validText(v string, max int) bool {
	if len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func validActor(a Actor) bool {
	return idPattern.MatchString(a.ID) && a.Name != "" && validText(a.Name, 128)
}
func mailbox(v string) bool {
	a, e := mail.ParseAddress(v)
	if e != nil || a.Address != v || len(v) > 254 || strings.TrimSpace(v) != v || !validText(v, 254) {
		return false
	}
	for _, c := range v {
		if c > 127 {
			return false
		}
	}
	return strings.Contains(v, "@")
}
func validEndpoint(v string) bool {
	u, e := url.Parse(v)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(v) > 2048 {
		return false
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return false
		}
	}
	return validText(v, 2048)
}
func (s Settings) Validate() error {
	for _, ca := range []string{s.SMTP.CA, s.Webhook.CA, s.SMS.CA} {
		if _, e := parseCA(ca); e != nil {
			return ErrInvalid
		}
	}
	if s.Revision < 0 || s.Revision >= 1<<53 || !validText(s.SMTP.SubjectPrefix, 120) || len(s.SMTP.CA) > 65536 || len(s.Webhook.CA) > 65536 || len(s.SMS.CA) > 65536 {
		return ErrInvalid
	}
	if v := s.SMTP; v.Enabled {
		if v.Host == "" || !validText(v.Host, 253) || strings.ContainsAny(v.Host, "/\\@ \t") || v.Port < 1 || v.Port > 65535 || v.Mode != "tls" && v.Mode != "starttls" || !mailbox(v.From) || !validText(v.Username, 254) {
			return ErrInvalid
		}
		if strings.Contains(v.Host, ":") && net.ParseIP(v.Host) == nil {
			return ErrInvalid
		}
	}
	for _, v := range []HTTPChannel{s.Webhook, s.SMS} {
		if v.Enabled && !validEndpoint(v.URL) {
			return ErrInvalid
		}
	}
	return nil
}
func (p PreferencesInput) Validate() error {
	if p.Revision < 1 || p.Revision >= 1<<53 || p.Language != "auto" && p.Language != "en" && p.Language != "zh-CN" || p.Email != "" && !mailbox(p.Email) || p.Phone != "" && !phonePattern.MatchString(p.Phone) || len(p.Topics) > len(Topics) {
		return ErrInvalid
	}
	for topic, rows := range p.Topics {
		if !slices.Contains(Topics, topic) || len(rows) > len(Channels) {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, channel := range rows {
			if !slices.Contains(Channels, channel) || seen[channel] {
				return ErrInvalid
			}
			seen[channel] = true
		}
	}
	return nil
}
