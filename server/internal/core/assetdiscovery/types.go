// Package assetdiscovery owns organization-scoped source configuration, sync
// policies, observed endpoints, durable runs and one-use import previews.
package assetdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

var (
	ErrInvalid  = errors.New("invalid asset discovery input")
	ErrConflict = errors.New("asset discovery revision conflict")
	ErrCapacity = errors.New("asset discovery capacity reached")
	ErrNotFound = errors.New("asset discovery resource not found")
	ErrDenied   = errors.New("asset discovery authorization revoked")
	ErrClosed   = errors.New("asset discovery runtime closed")
	ErrPreview  = errors.New("asset discovery preview expired, changed or consumed")
)

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Credential struct {
	Password             string `json:"password,omitempty"`
	PrivateKey           string `json:"private_key,omitempty"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitempty"`
}
type SourceInput struct {
	Cloud           *cloudinventory.Config     `json:"cloud,omitempty"`
	CloudCredential *cloudinventory.Credential `json:"cloud_credential,omitempty"`
	Provider        string                     `json:"provider,omitempty"`
	RequestID       string                     `json:"request_id,omitempty"`
	Revision        int                        `json:"revision"`
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	Enabled         bool                       `json:"enabled"`
	Targets         []string                   `json:"targets"`
	Exclude         []string                   `json:"exclude"`
	Ports           []int                      `json:"ports"`
	TimeoutMS       int                        `json:"timeout_ms"`
	Concurrency     int                        `json:"concurrency"`
	GatewayID       string                     `json:"gateway_id,omitempty"`
	Template        assets.Input               `json:"template"`
	Credential      *Credential                `json:"credential,omitempty"`
}
type Source struct {
	Cloud                     *cloudinventory.Config `json:"cloud,omitempty"`
	CloudCredentialConfigured bool                   `json:"cloud_credential_configured,omitempty"`
	Provider                  string                 `json:"provider"`
	ID                        string                 `json:"id"`
	Revision                  int                    `json:"revision"`
	Name                      string                 `json:"name"`
	Description               string                 `json:"description"`
	Enabled                   bool                   `json:"enabled"`
	Targets                   []string               `json:"targets"`
	Exclude                   []string               `json:"exclude"`
	Ports                     []int                  `json:"ports"`
	AddressCount              int                    `json:"address_count"`
	TimeoutMS                 int                    `json:"timeout_ms"`
	Concurrency               int                    `json:"concurrency"`
	GatewayID                 string                 `json:"gateway_id,omitempty"`
	Template                  json.RawMessage        `json:"template"`
	CredentialConfigured      bool                   `json:"credential_configured"`
	KeyFingerprint            string                 `json:"key_fingerprint,omitempty"`
	CreatedAt                 time.Time              `json:"created_at"`
	UpdatedAt                 time.Time              `json:"updated_at"`
}
type PolicyInput struct {
	OverwriteManualChanges bool                 `json:"overwrite_manual_changes"`
	SourceRevision         int                  `json:"source_revision"`
	RequestID              string               `json:"request_id,omitempty"`
	Revision               int                  `json:"revision"`
	SourceID               string               `json:"source_id"`
	Name                   string               `json:"name"`
	Enabled                bool                 `json:"enabled"`
	NamePrefix             string               `json:"name_prefix"`
	NodeID                 string               `json:"node_id,omitempty"`
	Group                  string               `json:"group"`
	MatchCIDRs             []string             `json:"match_cidrs"`
	UpdateExisting         bool                 `json:"update_existing"`
	AutoImport             bool                 `json:"auto_import"`
	TrustNewSSHKeys        bool                 `json:"trust_new_ssh_keys"`
	MissingAction          string               `json:"missing_action"`
	MissingThreshold       int                  `json:"missing_threshold"`
	Schedule               *operations.Schedule `json:"schedule,omitempty"`
}
type Policy struct {
	CalendarWatermark string                `json:"calendar_watermark,omitempty"`
	SkippedTriggers   int                   `json:"skipped_triggers"`
	LastScheduleError string                `json:"last_schedule_error,omitempty"`
	Deleted           bool                  `json:"deleted,omitempty"`
	Origin            accesspolicies.Origin `json:"origin"`
	ID                string                `json:"id"`
	PolicyInput
	Owner     Actor     `json:"owner"`
	NextRunAt time.Time `json:"next_run_at,omitzero"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Finding struct {
	Cloud          *cloudinventory.Instance `json:"cloud,omitempty"`
	SourceRevision int                      `json:"source_revision"`
	ID             string                   `json:"id"`
	SourceID       string                   `json:"source_id"`
	Revision       int                      `json:"revision"`
	Host           string                   `json:"host"`
	Port           int                      `json:"port"`
	Protocol       string                   `json:"protocol"`
	inventoryprobe.Result
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	LastScanned       time.Time `json:"last_scanned"`
	ConsecutiveMisses int       `json:"consecutive_misses"`
	AssetID           string    `json:"asset_id,omitempty"`
	SyncState         string    `json:"sync_state"`
	SyncError         string    `json:"sync_error,omitempty"`
}
type Run struct {
	ReviewID       string                `json:"review_id,omitempty"`
	Origin         accesspolicies.Origin `json:"origin"`
	ID             string                `json:"id"`
	Revision       int                   `json:"revision"`
	SourceID       string                `json:"source_id"`
	SourceRevision int                   `json:"source_revision"`
	PolicyID       string                `json:"policy_id,omitempty"`
	PolicyRevision int                   `json:"policy_revision,omitempty"`
	Actor          Actor                 `json:"actor"`
	Trigger        string                `json:"trigger"`
	State          string                `json:"state"`
	Total          int                   `json:"total"`
	Completed      int                   `json:"completed"`
	Reachable      int                   `json:"reachable"`
	Imported       int                   `json:"imported"`
	Updated        int                   `json:"updated"`
	Conflicts      int                   `json:"conflicts"`
	ErrorCode      string                `json:"error_code,omitempty"`
	StartedAt      time.Time             `json:"started_at"`
	FinishedAt     time.Time             `json:"finished_at,omitzero"`
}
type RunInput struct {
	SourceID       string `json:"source_id"`
	SourceRevision int    `json:"source_revision"`
	PolicyID       string `json:"policy_id,omitempty"`
	PolicyRevision int    `json:"policy_revision,omitempty"`
	RequestID      string `json:"request_id"`
}
type PreviewInput struct {
	SourceID       string      `json:"source_id"`
	SourceRevision int         `json:"source_revision"`
	PolicyID       string      `json:"policy_id"`
	PolicyRevision int         `json:"policy_revision"`
	Findings       []Selection `json:"findings"`
}
type Selection struct {
	ID                 string `json:"id"`
	Revision           int    `json:"revision"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
}
type Preview struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Results   []Finding `json:"results"`
}
type ImportInput struct {
	Token     string `json:"token"`
	RequestID string `json:"request_id"`
}
type ImportResult struct {
	RequestID string    `json:"request_id"`
	Imported  int       `json:"imported"`
	Updated   int       `json:"updated"`
	Results   []Finding `json:"results"`
}
type Audit struct {
	Before            json.RawMessage `json:"before,omitempty"`
	After             json.RawMessage `json:"after,omitempty"`
	At                time.Time       `json:"at"`
	Actor             Actor           `json:"actor"`
	Action            string          `json:"action"`
	SourceID          string          `json:"source_id,omitempty"`
	PolicyID          string          `json:"policy_id,omitempty"`
	RunID             string          `json:"run_id,omitempty"`
	Revision          int             `json:"revision,omitempty"`
	CredentialChanged bool            `json:"credential_changed,omitempty"`
	Count             int             `json:"count,omitempty"`
}

type originKey struct{}

func WithOrigin(ctx context.Context, origin accesspolicies.Origin) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}
func Origin(ctx context.Context) accesspolicies.Origin {
	value, _ := ctx.Value(originKey{}).(accesspolicies.Origin)
	return value
}

type ReviewRequired struct {
	ID        string
	State     string
	ExpiresAt time.Time
}

func (e *ReviewRequired) Error() string { return "asset discovery gateway review required" }
