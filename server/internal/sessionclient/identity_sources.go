package sessionclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"regexp"
	"slices"
)

// Transport DTOs intentionally avoid linking the server's IdP runtimes into jms.
type IdentitySourceInput struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Enabled   bool   `json:"enabled"`
	Archived  bool   `json:"archived"`
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id,omitempty"`
}
type IdentitySource struct {
	IdentitySourceInput
	ID        string `json:"id"`
	UpdatedAt string `json:"updated_at"`
}
type IdentitySyncOperation struct {
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
	PreviewID string `json:"preview_id,omitempty"`
}

const identitySourcesBase = "/api/v1/identity-sources"

var identityRequest = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

func (c *Client) IdentitySources(ctx context.Context) ([]IdentitySource, error) {
	out := []IdentitySource{}
	e := c.jobRequest(ctx, "GET", identitySourcesBase, nil, &out)
	return out, e
}
func (c *Client) IdentitySource(ctx context.Context, id string) (IdentitySource, error) {
	var out IdentitySource
	if !identityscope.ValidID(id) {
		return out, errors.New("invalid identity source ID")
	}
	e := c.jobRequest(ctx, "GET", identitySourcesBase+"/"+id, nil, &out)
	return out, e
}
func (c *Client) SaveIdentitySource(ctx context.Context, id string, in IdentitySourceInput) (IdentitySource, error) {
	var out IdentitySource
	if id != "" && !identityscope.ValidID(id) || !slices.Contains([]string{"ldap", "oidc", "cas", "saml"}, in.Kind) || in.Name == "" || in.Revision < 0 || !identityRequest.MatchString(in.RequestID) {
		return out, errors.New("invalid identity source input")
	}
	method, path := "POST", identitySourcesBase
	if id != "" {
		method, path = "PUT", path+"/"+id
	}
	e := c.jobRequest(ctx, method, path, in, &out)
	return out, e
}
func (c *Client) IdentitySourceAudit(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	e := c.jobRequest(ctx, "GET", identitySourcesBase+"/audit", nil, &out)
	return out, e
}
func (c *Client) DirectorySync(ctx context.Context, id, resource string, offset, limit int) (json.RawMessage, error) {
	var out json.RawMessage
	if !identityscope.ValidID(id) || !slices.Contains([]string{"", "entries", "runs", "audit"}, resource) || offset < 0 || limit < 1 || limit > 200 {
		return out, errors.New("invalid directory synchronization query")
	}
	path := identitySourcesBase + "/" + id + "/sync"
	if resource != "" {
		path += fmt.Sprintf("/%s?offset=%d&limit=%d", resource, offset, limit)
	}
	e := c.jobRequest(ctx, "GET", path, nil, &out)
	return out, e
}
func (c *Client) SaveDirectorySync(ctx context.Context, id string, in json.RawMessage) (json.RawMessage, error) {
	var out json.RawMessage
	var envelope struct {
		Revision  int    `json:"revision"`
		RequestID string `json:"request_id"`
	}
	if !identityscope.ValidID(id) || len(in) > 1<<20 || json.Unmarshal(in, &envelope) != nil || envelope.Revision < 0 || !identityRequest.MatchString(envelope.RequestID) {
		return out, errors.New("invalid directory synchronization settings")
	}
	e := c.jobRequest(ctx, "PUT", identitySourcesBase+"/"+id+"/sync", in, &out)
	return out, e
}
func (c *Client) DirectorySyncAction(ctx context.Context, id, action string, in IdentitySyncOperation) (json.RawMessage, error) {
	var out json.RawMessage
	if !identityscope.ValidID(id) || !slices.Contains([]string{"preview", "apply", "abort"}, action) || in.Revision < 1 || !identityRequest.MatchString(in.RequestID) || action != "preview" && in.PreviewID == "" {
		return out, errors.New("invalid directory synchronization action")
	}
	e := c.jobRequest(ctx, "POST", identitySourcesBase+"/"+id+"/sync/"+action, in, &out)
	return out, e
}
