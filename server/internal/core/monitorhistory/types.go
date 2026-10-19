// Package monitorhistory persists bounded, encrypted SSH monitoring history.
package monitorhistory

import (
	"errors"
	"math"
	"regexp"
	"time"
)

const (
	Retention   = 7 * 24 * time.Hour
	MaxSegments = 100000
	MaxPoints   = 1440
	cacheSize   = 8
)

var (
	ErrInvalid     = errors.New("invalid monitoring history request")
	ErrCorrupt     = errors.New("monitoring history integrity check failed")
	ErrCapacity    = errors.New("monitoring history capacity reached")
	ErrConflict    = errors.New("monitoring sample timestamp conflict")
	ErrClosed      = errors.New("monitoring history closed")
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
	keyPattern     = regexp.MustCompile(`^[a-f0-9]{24}-[0-9]{10}$`)
	bindingPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var Metrics = []string{"cpu_percent", "memory_percent", "disk_percent", "latency_ms", "network_rx_bps", "network_tx_bps"}

type Sample struct {
	At      time.Time          `json:"at"`
	Binding string             `json:"binding"`
	State   string             `json:"state"`
	Values  map[string]float64 `json:"values"`
}
type Statistic struct {
	Mean    float64 `json:"mean"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Samples int     `json:"samples"`
}
type Point struct {
	At         time.Time            `json:"at"`
	LastSample time.Time            `json:"last_sample,omitzero"`
	State      string               `json:"state"`
	Samples    int                  `json:"samples"`
	Online     int                  `json:"online"`
	Offline    int                  `json:"offline"`
	Values     map[string]Statistic `json:"values"`
}
type Health struct {
	ErrorCode    string    `json:"error_code,omitempty"`
	LastFailure  time.Time `json:"last_failure,omitzero"`
	Segments     int       `json:"segments"`
	Capacity     int       `json:"capacity"`
	PrunePending bool      `json:"prune_pending"`
}
type Page struct {
	AssetID       string    `json:"asset_id"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	StepSeconds   int       `json:"step_seconds"`
	RetentionDays int       `json:"retention_days"`
	Resolution    string    `json:"resolution"`
	Results       []Point   `json:"results"`
	Health        Health    `json:"health"`
}
type segment struct {
	Version int       `json:"version"`
	AssetID string    `json:"asset_id"`
	Hour    time.Time `json:"hour"`
	Samples []Sample  `json:"samples"`
}

func validSample(s Sample) bool {
	if s.At.IsZero() || s.At.Year() < 1970 || s.At.Year() > 9999 || !bindingPattern.MatchString(s.Binding) || s.State != "online" && s.State != "offline" || len(s.Values) > len(Metrics) || s.State == "offline" && len(s.Values) != 0 {
		return false
	}
	for name, value := range s.Values {
		found := false
		for _, metric := range Metrics {
			if name == metric {
				found = true
				break
			}
		}
		if !found || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e15 {
			return false
		}
		if (name == "cpu_percent" || name == "memory_percent" || name == "disk_percent") && value > 100 {
			return false
		}
	}
	return true
}
