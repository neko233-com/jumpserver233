package sessionclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Responses expose metadata only. File bytes are write-only API inputs.
type AccountImportRequest struct {
	Format       string `json:"format"`
	Content      []byte `json:"content"`
	RequestID    string `json:"request_id"`
	PreviewToken string `json:"preview_token,omitempty"`
}

type AccountImportSummary struct {
	Line               int    `json:"line"`
	Action             string `json:"action"`
	AssetID            string `json:"asset_id"`
	AssetName          string `json:"asset_name"`
	AccountID          string `json:"account_id"`
	Username           string `json:"username"`
	CredentialType     string `json:"credential_type"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	Active             bool   `json:"active"`
	CredentialReplaced bool   `json:"credential_replaced"`
	RotationChanged    bool   `json:"rotation_changed"`
	Version            string `json:"version,omitempty"`
}
type AccountImportIssue struct {
	Line  int    `json:"line"`
	Field string `json:"field,omitempty"`
	Code  string `json:"code"`
}
type AccountImportPreview struct {
	RequestID string                 `json:"request_id"`
	Rows      []AccountImportSummary `json:"rows"`
	Issues    []AccountImportIssue   `json:"issues"`
	Token     string                 `json:"preview_token,omitempty"`
	ExpiresAt time.Time              `json:"expires_at,omitzero"`
	Committed bool                   `json:"committed"`
}
type AccountImportActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type AccountImportReceipt struct {
	RequestID string                 `json:"request_id"`
	Actor     AccountImportActor     `json:"actor"`
	CreatedAt time.Time              `json:"created_at"`
	Rows      []AccountImportSummary `json:"rows"`
}
type AccountImportHistory struct {
	RequestID string             `json:"request_id"`
	Actor     AccountImportActor `json:"actor"`
	CreatedAt time.Time          `json:"created_at"`
	Count     int                `json:"count"`
	Created   int                `json:"created"`
	Updated   int                `json:"updated"`
}

func (c *Client) PreviewAccountImport(ctx context.Context, in AccountImportRequest) (AccountImportPreview, error) {
	var out AccountImportPreview
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/accounts/imports/preview", in, &out)
	return out, e
}
func (c *Client) CommitAccountImport(ctx context.Context, in AccountImportRequest) (AccountImportReceipt, error) {
	var out AccountImportReceipt
	e := c.jobRequest(ctx, http.MethodPost, "/api/v1/accounts/imports", in, &out)
	return out, e
}
func (c *Client) AccountImportTemplate(ctx context.Context, format string) ([]byte, error) {
	var out struct {
		Content []byte `json:"content"`
	}
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/accounts/imports/template?format="+url.QueryEscape(format), nil, &out)
	return out.Content, e
}
func (c *Client) AccountImportHistory(ctx context.Context, offset, limit int) ([]AccountImportHistory, int, error) {
	var out struct {
		Results []AccountImportHistory `json:"results"`
		Total   int                    `json:"total"`
	}
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/accounts/imports?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out.Results, out.Total, e
}
func (c *Client) AccountImportReceipt(ctx context.Context, id, actor string) (AccountImportReceipt, error) {
	var out AccountImportReceipt
	e := c.jobRequest(ctx, http.MethodGet, "/api/v1/accounts/imports/"+url.PathEscape(id)+"?actor_id="+url.QueryEscape(actor), nil, &out)
	return out, e
}
