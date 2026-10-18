// Package monitoralerts evaluates platform-observed SSH monitoring samples.
// It never connects to hosts or receives credentials or remote command output.
package monitoralerts

import (
	"context"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid monitoring alert input")
	ErrDenied   = errors.New("monitoring alert permission denied")
	ErrNotFound = errors.New("monitoring alert not found")
	ErrConflict = errors.New("monitoring alert revision changed")
	ErrCapacity = errors.New("monitoring alert capacity reached")
	ErrClosed   = errors.New("monitoring alert service closed")
)

const (
	MaxRules      = 100
	MaxInstances  = 50000
	MaxAlerts     = 20000
	MaxEvents     = 20000
	MaxAudit      = 20000
	maxStateBytes = 64 << 20
)

var Metrics = []string{"cpu_percent", "memory_percent", "disk_percent", "latency_ms", "network_rx_bps", "network_tx_bps", "offline", "no_data"}
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Scope struct {
	All      bool     `json:"all"`
	AssetIDs []string `json:"asset_ids"`
	NodeIDs  []string `json:"node_ids"`
}
type Input struct {
	Revision          int     `json:"revision"`
	Name              string  `json:"name"`
	Enabled           bool    `json:"enabled"`
	Metric            string  `json:"metric"`
	Scope             Scope   `json:"scope"`
	Threshold         float64 `json:"threshold"`
	RecoveryThreshold float64 `json:"recovery_threshold"`
	ForSamples        int     `json:"for_samples"`
	ForSeconds        int     `json:"for_seconds"`
	RecoverySamples   int     `json:"recovery_samples"`
	RecoverySeconds   int     `json:"recovery_seconds"`
	MaxAgeSeconds     int     `json:"max_age_seconds"`
	RepeatSeconds     int     `json:"repeat_seconds"`
}
type Rule struct {
	ID         string `json:"id"`
	Definition int    `json:"definition"`
	Input
	Owner      Actor     `json:"owner"`
	UpdatedAt  time.Time `json:"updated_at"`
	MutedUntil time.Time `json:"muted_until,omitzero"`
	MuteReason string    `json:"mute_reason,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}
type Alert struct {
	ID                string    `json:"id"`
	Revision          int       `json:"revision"`
	RuleID            string    `json:"rule_id"`
	RuleRevision      int       `json:"rule_revision"`
	RuleName          string    `json:"rule_name"`
	AssetID           string    `json:"asset_id"`
	AssetName         string    `json:"asset_name"`
	Metric            string    `json:"metric"`
	State             string    `json:"state"`
	Reason            string    `json:"reason,omitempty"`
	Value             *float64  `json:"value,omitempty"`
	Threshold         float64   `json:"threshold"`
	RecoveryThreshold float64   `json:"recovery_threshold"`
	StartedAt         time.Time `json:"started_at"`
	LastObservedAt    time.Time `json:"last_observed_at"`
	EndedAt           time.Time `json:"ended_at,omitzero"`
	AcknowledgedAt    time.Time `json:"acknowledged_at,omitzero"`
	AcknowledgedBy    Actor     `json:"acknowledged_by,omitzero"`
	Comment           string    `json:"comment,omitempty"`
}
type Audit struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Actor  Actor     `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Reason string    `json:"reason,omitempty"`
}
type Event struct {
	ID        string
	AlertID   string
	AssetID   string
	AssetName string
	State     string
	At        time.Time
}
type Source struct {
	AssetID, AssetName, Binding string
	Nodes                       []string
	At                          time.Time
	State                       string
	Values                      map[string]float64
}
type Runner struct {
	// Acquire fences source reads and commits against organization/access edits.
	Acquire    func(context.Context) (func(), error)
	Sources    func(context.Context) ([]Source, error)
	Authorized func(context.Context, Actor) bool
}
type Health struct {
	LastEvaluation time.Time `json:"last_evaluation,omitzero"`
	ErrorCode      string    `json:"error_code,omitempty"`
	Rules          int       `json:"rules"`
	Firing         int       `json:"firing"`
	Pending        int       `json:"pending"`
}
type Page[T any] struct {
	Results []T `json:"results"`
	Total   int `json:"total"`
}

func textOK(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func actorOK(a Actor) bool  { return idPattern.MatchString(a.ID) && textOK(a.Name, 128) }
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func validate(in Input) error {
	if !textOK(in.Name, 120) || strings.TrimSpace(in.Name) == "" || in.Revision < 0 || in.Revision > 1e9 || !slices.Contains(Metrics, in.Metric) || !finite(in.Threshold) || !finite(in.RecoveryThreshold) || in.Threshold < 0 || in.RecoveryThreshold < 0 || in.RecoveryThreshold >= in.Threshold || in.ForSamples < 1 || in.ForSamples > 30 || in.RecoverySamples < 1 || in.RecoverySamples > 30 || in.ForSeconds < 0 || in.ForSeconds > 3600 || in.RecoverySeconds < 0 || in.RecoverySeconds > 3600 || in.MaxAgeSeconds < 30 || in.MaxAgeSeconds > 3600 || in.RepeatSeconds != 0 && (in.RepeatSeconds < 60 || in.RepeatSeconds > 86400) {
		return ErrInvalid
	}
	if strings.HasSuffix(in.Metric, "_percent") && in.Threshold > 100 {
		return ErrInvalid
	}
	if in.Threshold > 1e12 {
		return ErrInvalid
	}
	if in.Metric == "offline" || in.Metric == "no_data" {
		if in.Threshold != 1 || in.RecoveryThreshold != 0 {
			return ErrInvalid
		}
	}
	if in.Metric == "no_data" && (in.ForSamples != 1 || in.RecoverySamples != 1) {
		return ErrInvalid
	}
	if len(in.Scope.AssetIDs) > 500 || len(in.Scope.NodeIDs) > 100 || in.Scope.All && (len(in.Scope.AssetIDs) > 0 || len(in.Scope.NodeIDs) > 0) || !in.Scope.All && len(in.Scope.AssetIDs)+len(in.Scope.NodeIDs) == 0 {
		return ErrInvalid
	}
	for _, ids := range [][]string{in.Scope.AssetIDs, in.Scope.NodeIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !idPattern.MatchString(id) || seen[id] {
				return ErrInvalid
			}
			seen[id] = true
		}
	}
	return nil
}
func matches(scope Scope, v Source) bool {
	if scope.All || slices.Contains(scope.AssetIDs, v.AssetID) {
		return true
	}
	for _, n := range v.Nodes {
		if slices.Contains(scope.NodeIDs, n) {
			return true
		}
	}
	return false
}
