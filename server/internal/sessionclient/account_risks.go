package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// These DTOs intentionally contain only metadata, keeping Vault and database
// implementation dependencies out of the platform CLI.
type AccountRiskPolicy struct {
	Revision              int                `json:"revision"`
	Enabled               bool               `json:"enabled"`
	IntervalHours         int                `json:"interval_hours"`
	MinPasswordLength     int                `json:"min_password_length"`
	MaxCredentialAgeDays  int                `json:"max_credential_age_days"`
	UnusedAccountDays     int                `json:"unused_account_days"`
	ResolvedRetentionDays int                `json:"resolved_retention_days"`
	AuditRetentionDays    int                `json:"audit_retention_days"`
	IncludeDisabled       bool               `json:"include_disabled"`
	Checks                []string           `json:"checks"`
	Owner                 AccountImportActor `json:"owner"`
	NextRun               time.Time          `json:"next_run,omitzero"`
	LastError             string             `json:"last_error,omitempty"`
}
type AccountRiskRef struct {
	AssetID   string `json:"asset_id"`
	AccountID string `json:"account_id"`
	AssetName string `json:"asset_name"`
	Username  string `json:"username"`
}
type AccountRiskFinding struct {
	AccountRiskRef
	ID             string           `json:"id"`
	Kind           string           `json:"kind"`
	Severity       string           `json:"severity"`
	Reasons        []string         `json:"reasons"`
	CredentialType string           `json:"credential_type"`
	Active         bool             `json:"active"`
	SourceVersion  string           `json:"source_version"`
	PolicyRevision int              `json:"policy_revision"`
	Revision       int              `json:"revision"`
	State          string           `json:"state"`
	Note           string           `json:"note"`
	FirstSeen      time.Time        `json:"first_seen"`
	LastSeen       time.Time        `json:"last_seen"`
	ResolvedAt     time.Time        `json:"resolved_at,omitzero"`
	LastUsedAt     time.Time        `json:"last_used_at,omitzero"`
	RotatedAt      time.Time        `json:"rotated_at"`
	Occurrences    int              `json:"occurrences"`
	PeerCount      int              `json:"peer_count"`
	Peers          []AccountRiskRef `json:"peers"`
	Outdated       bool             `json:"outdated"`
}
type AccountRiskScan struct {
	ID             string             `json:"id"`
	RequestID      string             `json:"request_id"`
	Actor          AccountImportActor `json:"actor"`
	PolicyRevision int                `json:"policy_revision"`
	State          string             `json:"state"`
	ErrorCode      string             `json:"error_code,omitempty"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at,omitzero"`
	Accounts       int                `json:"accounts"`
	Open           int                `json:"open"`
	Resolved       int                `json:"resolved"`
}
type AccountRiskAudit struct {
	At        time.Time          `json:"at"`
	Actor     AccountImportActor `json:"actor"`
	Action    string             `json:"action"`
	FindingID string             `json:"finding_id,omitempty"`
	Before    string             `json:"before,omitempty"`
	After     string             `json:"after,omitempty"`
	ScanID    string             `json:"scan_id,omitempty"`
}
type AccountRiskQuery struct {
	State, Kind, AssetID, Search string
	Offset, Limit                int
}

func (q AccountRiskQuery) values() string {
	v := url.Values{}
	v.Set("state", q.State)
	v.Set("kind", q.Kind)
	v.Set("asset_id", q.AssetID)
	v.Set("q", q.Search)
	v.Set("offset", strconv.Itoa(q.Offset))
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	v.Set("limit", strconv.Itoa(limit))
	return v.Encode()
}
func (c *Client) AccountRiskPolicy(ctx context.Context) (AccountRiskPolicy, error) {
	var out AccountRiskPolicy
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/risks/policy", nil, &out)
	return out, e
}
func (c *Client) SaveAccountRiskPolicy(ctx context.Context, in AccountRiskPolicy) (AccountRiskPolicy, error) {
	var out AccountRiskPolicy
	e := c.jobRequest(ctx, "PUT", "/api/v1/accounts/risks/policy", in, &out)
	return out, e
}
func (c *Client) ScanAccountRisks(ctx context.Context, revision int, requestID string) (AccountRiskScan, error) {
	var out AccountRiskScan
	e := c.jobRequest(ctx, "POST", "/api/v1/accounts/risks/scans", map[string]any{"revision": revision, "request_id": requestID}, &out)
	return out, e
}
func (c *Client) CancelAccountRiskScan(ctx context.Context, id string) error {
	return c.jobRequest(ctx, "DELETE", "/api/v1/accounts/risks/scans/"+url.PathEscape(id), nil, nil)
}
func (c *Client) AccountRiskFindings(ctx context.Context, q AccountRiskQuery) ([]AccountRiskFinding, int, error) {
	var out struct {
		Results []AccountRiskFinding `json:"results"`
		Total   int                  `json:"total"`
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/risks?"+q.values(), nil, &out)
	return out.Results, out.Total, e
}
func (c *Client) ReviewAccountRisk(ctx context.Context, id string, revision int, action, note string) (AccountRiskFinding, error) {
	var out AccountRiskFinding
	e := c.jobRequest(ctx, "POST", "/api/v1/accounts/risks/"+url.PathEscape(id)+"/review", map[string]any{"revision": revision, "action": action, "note": note}, &out)
	return out, e
}
func (c *Client) AccountRiskScans(ctx context.Context, offset, limit int) ([]AccountRiskScan, int, error) {
	var out struct {
		Results []AccountRiskScan `json:"results"`
		Total   int               `json:"total"`
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/risks/scans?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out.Results, out.Total, e
}
func (c *Client) AccountRiskAudit(ctx context.Context, offset, limit int) ([]AccountRiskAudit, int, error) {
	var out struct {
		Results []AccountRiskAudit `json:"results"`
		Total   int                `json:"total"`
	}
	e := c.jobRequest(ctx, "GET", "/api/v1/accounts/risks/audit?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out.Results, out.Total, e
}
func (c *Client) ExportAccountRisks(ctx context.Context, q AccountRiskQuery) ([]byte, error) {
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/accounts/risks/export"
	endpoint.RawQuery = q.values()
	r, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if e != nil {
		return nil, e
	}
	if e = c.authorizeRequest(r); e != nil {
		return nil, e
	}
	response, e := c.http.Do(r)
	if e != nil {
		return nil, fmt.Errorf("account risk export request failed")
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		var v struct {
			Code string `json:"error_code"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&v)
		return nil, &APIError{StatusCode: response.StatusCode, Detail: "account risk export rejected"}
	}
	if response.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		return nil, fmt.Errorf("invalid account risk export response")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (128<<20)+1))
	if e != nil || len(raw) > 128<<20 {
		return nil, fmt.Errorf("account risk export is too large")
	}
	return raw, nil
}
