// Package loginaudit holds platform identity events. Credentials and protocol
// request bodies never enter this package.
package loginaudit

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid platform login audit event")
	ErrNotFound = errors.New("platform login audit event not found")
	ErrClosed   = errors.New("platform login audit closed")
)

const (
	SegmentSize = 256
	MaxRecords  = 100000
	Retention   = 365 * 24 * time.Hour
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_@.+-]{1,128}$`)
var methods = []string{"local", "ldap", "oidc", "saml", "cas", "passkey", "radius", "unknown"}
var outcomes = []string{"succeeded", "failed", "denied", "throttled", "challenge", "external_verified", "cancelled", "service_error", "invalid_request", "review_pending", "review_approved", "review_denied", "review_expired", "review_cancelled", "review_consumed", "review_invalidated", "policy_notified", "started", "exported"}
var stages = []string{"primary", "mfa", "external", "session", "review", "logout", "export"}
var reasons = []string{"", "password_change_required", "credentials_rejected", "second_factor_required", "enrollment_required", "second_factor_rejected", "identity_rejected", "flow_rejected", "origin_rejected", "source_policy", "attempt_limit", "authentication_unavailable", "request_invalid", "session_issued", "review_required", "review_completed", "user_cancelled", "external_identity_verified"}

type Input struct {
	// ID and At are for trusted, already durable native review events.
	ID                             string
	At                             time.Time
	Method, Stage, Outcome, Reason string
	UserID, Username               string
	ActorID, Actor                 string
	AttemptedName                  string
	SourceIP, Client, ReviewID     string
}
type Record struct {
	ID            string    `json:"id"`
	Sequence      uint64    `json:"sequence"`
	At            time.Time `json:"at"`
	Method        string    `json:"method"`
	Stage         string    `json:"stage"`
	Outcome       string    `json:"outcome"`
	Reason        string    `json:"reason,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
	Username      string    `json:"username,omitempty"`
	ActorID       string    `json:"actor_id,omitempty"`
	Actor         string    `json:"actor,omitempty"`
	AttemptedName string    `json:"attempted_name,omitempty"`
	SourceIP      string    `json:"source_ip"`
	Client        string    `json:"client"`
	ReviewID      string    `json:"review_id,omitempty"`
	Notification  string    `json:"notification,omitempty"`
}
type Filter struct {
	Offset, Limit                            int
	Method, Outcome, Query, SourceIP, UserID string
	From, To                                 time.Time
}
type Page struct {
	Results []Record `json:"results"`
	Total   int      `json:"total"`
}
type Health struct {
	Records            int       `json:"records"`
	FirstSequence      uint64    `json:"first_sequence"`
	LastSequence       uint64    `json:"last_sequence"`
	ErrorCode          string    `json:"error_code,omitempty"`
	LastFailure        time.Time `json:"last_failure,omitzero"`
	PrunePending       bool      `json:"prune_pending"`
	AggregationLimited bool      `json:"aggregation_limited"`
	ReviewErrorCode    string    `json:"review_error_code,omitempty"`
	ReviewGap          bool      `json:"review_gap"`
	LastReviewSync     time.Time `json:"last_review_sync,omitzero"`
}
type Summary struct {
	Total      int `json:"total"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	Denied     int `json:"denied"`
	Challenges int `json:"challenges"`
}
type SourceBatch struct {
	Events []Input
	Cursor string
	Gap    bool
}
type Source func(context.Context, string) (SourceBatch, error)

func clean(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func optionalID(v string) bool { return v == "" || idPattern.MatchString(v) }
func validIP(v string) bool {
	if v == "unknown" {
		return true
	}
	ip, e := netip.ParseAddr(v)
	return e == nil && ip.Zone() == "" && ip.Unmap().String() == v
}
func valid(r Record) bool {
	return idPattern.MatchString(r.ID) && r.Sequence > 0 && !r.At.IsZero() && slices.Contains(methods, r.Method) && slices.Contains(stages, r.Stage) && slices.Contains(outcomes, r.Outcome) && slices.Contains(reasons, r.Reason) && optionalID(r.UserID) && optionalID(r.ActorID) && optionalID(r.ReviewID) && clean(r.Username, 128) && clean(r.Actor, 128) && (r.AttemptedName == "" || namePattern.MatchString(r.AttemptedName)) && validIP(r.SourceIP) && slices.Contains([]string{"browser", "api", "unknown"}, r.Client) && slices.Contains([]string{"", "platform_login_succeeded", "platform_login_new_source", "platform_login_failures", "platform_review_pending", "platform_review_approved", "platform_review_denied", "platform_review_expired", "platform_review_cancelled", "platform_review_consumed", "platform_review_invalidated", "platform_policy_notified"}, r.Notification) && (r.Outcome != "succeeded" || r.UserID != "")
}
