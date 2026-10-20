package sessionclient

import (
	"context"
	"errors"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"slices"
)

type EnterpriseLoginConfig struct {
	Provider          string   `json:"provider"`
	ClientID          string   `json:"client_id"`
	TenantID          string   `json:"tenant_id"`
	AgentID           string   `json:"agent_id"`
	Region            string   `json:"region"`
	OAuthVersion      string   `json:"oauth_version"`
	CallbackURL       string   `json:"callback_url"`
	Scopes            []string `json:"scopes"`
	CAPEM             string   `json:"ca_pem"`
	AllowLoopbackHTTP bool     `json:"allow_loopback_http"`
	Enabled           bool     `json:"enabled"`
	ProvisionNew      bool     `json:"provision_new"`
	Revision          int      `json:"revision"`
}
type EnterpriseLoginInput struct {
	EnterpriseLoginConfig
	ClientSecret string `json:"client_secret,omitempty"`
	ClearSecret  bool   `json:"clear_secret"`
	RequestID    string `json:"request_id"`
}
type EnterpriseLoginSettings struct {
	EnterpriseLoginConfig
	HasClientSecret bool `json:"has_client_secret"`
}
type EnterpriseLoginAudit struct {
	At            string `json:"at"`
	ActorID       string `json:"actor_id"`
	Actor         string `json:"actor"`
	Revision      int    `json:"revision"`
	SecretChanged bool   `json:"secret_changed"`
}

func enterpriseLoginPath(id, kind string) (string, error) {
	if !identityscope.ValidID(id) || !identityscope.NativeKind(kind) {
		return "", errors.New("invalid enterprise identity source")
	}
	return identityscope.Prefix(id) + "/api/v1/settings/security/" + kind, nil
}
func (c *Client) EnterpriseLogin(ctx context.Context, id, kind string) (EnterpriseLoginSettings, error) {
	var out EnterpriseLoginSettings
	path, e := enterpriseLoginPath(id, kind)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", path, nil, &out)
	return out, e
}
func (c *Client) SaveEnterpriseLogin(ctx context.Context, id, kind string, in EnterpriseLoginInput) (EnterpriseLoginSettings, error) {
	var out EnterpriseLoginSettings
	path, e := enterpriseLoginPath(id, kind)
	if e != nil {
		return out, e
	}
	if in.Provider != kind || in.Revision < 0 || !identityRequest.MatchString(in.RequestID) || len(in.ClientSecret) > 4096 || in.ClearSecret && in.ClientSecret != "" {
		return out, errors.New("invalid enterprise login settings")
	}
	in.Scopes = slices.Clone(in.Scopes)
	e = c.jobRequest(ctx, "PUT", path, in, &out)
	return out, e
}
func (c *Client) CheckEnterpriseLogin(ctx context.Context, id, kind string) (bool, error) {
	path, e := enterpriseLoginPath(id, kind)
	if e != nil {
		return false, e
	}
	var out struct {
		Available bool `json:"application_credentials_available"`
	}
	e = c.jobRequest(ctx, "POST", path+"/check", nil, &out)
	return out.Available, e
}
func (c *Client) EnterpriseLoginAudit(ctx context.Context, id, kind string) ([]EnterpriseLoginAudit, error) {
	path, e := enterpriseLoginPath(id, kind)
	if e != nil {
		return nil, e
	}
	out := []EnterpriseLoginAudit{}
	e = c.jobRequest(ctx, "GET", path+"/audit", nil, &out)
	return out, e
}
func (c *Client) PrepareEnterpriseLoginUser(ctx context.Context, id, kind, subject, alias string) (coreauth.User, error) {
	var out coreauth.User
	path, e := enterpriseLoginPath(id, kind)
	if e != nil {
		return out, e
	}
	if subject == "" || len(subject) > 1024 || len(alias) > 64 {
		return out, errors.New("invalid enterprise subject")
	}
	e = c.jobRequest(ctx, "POST", path+"/users", map[string]string{"subject": subject, "username": alias}, &out)
	return out, e
}
