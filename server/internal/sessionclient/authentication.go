package sessionclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/radiuslogin"
)

type RadiusSettingsInput = radiuslogin.Input
type RadiusSettings = radiuslogin.Snapshot
type RadiusAuditPage struct {
	Results []radiuslogin.Audit `json:"results"`
	Total   int                 `json:"total"`
}
type AuthenticationResult struct {
	PasswordChangeRequired bool                     `json:"password_change_required,omitempty"`
	PasswordChanged        bool                     `json:"password_changed,omitempty"`
	PasswordPolicy         *coreauth.PasswordPolicy `json:"policy,omitempty"`
	ChangeToken            string                   `json:"change_token,omitempty"`
	Active                 bool                     `json:"active,omitempty"`
	State                  string                   `json:"state,omitempty"`
	AccessToken            string                   `json:"access_token,omitempty"`
	ExpiresAt              time.Time                `json:"expires_at,omitzero"`
	User                   *coreauth.User           `json:"user,omitempty"`
	RadiusChallenge        bool                     `json:"radius_challenge_required,omitempty"`
	RadiusVerified         bool                     `json:"radius_primary_verified,omitempty"`
	RadiusFactor           bool                     `json:"radius_factor_required,omitempty"`
	ChallengeToken         string                   `json:"challenge_token,omitempty"`
	PendingToken           string                   `json:"pending_token,omitempty"`
	FactorToken            string                   `json:"factor_token,omitempty"`
	ReviewRequired         bool                     `json:"login_review_required,omitempty"`
	ReviewToken            string                   `json:"review_token,omitempty"`
	ReviewID               string                   `json:"review_id,omitempty"`
	MFARequired            bool                     `json:"mfa_required,omitempty"`
	MFASetupRequired       bool                     `json:"mfa_setup_required,omitempty"`
	SetupToken             string                   `json:"setup_token,omitempty"`
	Enrollment             *coreauth.MFAEnrollment  `json:"enrollment,omitempty"`
}
type AuthenticationInput struct {
	ChangeToken    string `json:"change_token,omitempty"`
	NewPassword    string `json:"new_password,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	OTP            string `json:"otp,omitempty"`
	Response       string `json:"response,omitempty"`
	ChallengeToken string `json:"challenge_token,omitempty"`
	PendingToken   string `json:"pending_token,omitempty"`
	FactorToken    string `json:"factor_token,omitempty"`
	ReviewToken    string `json:"review_token,omitempty"`
	SetupToken     string `json:"setup_token,omitempty"`
}

func (c *Client) Authentication(ctx context.Context, step string, in AuthenticationInput) (AuthenticationResult, error) {
	var out AuthenticationResult
	routes := map[string]string{"password-complete": "/api/v1/authentication/password-change/complete", "password-status": "/api/v1/authentication/password-change/pending", "password-cancel": "/api/v1/authentication/password-change/cancel", "login": "/api/v1/authentication/auth/", "radius-login": "/api/v1/authentication/radius/login", "radius-challenge": "/api/v1/authentication/radius/challenge", "radius-complete": "/api/v1/authentication/radius/complete", "factor-complete": "/api/v1/authentication/factor/complete", "factor-cancel": "/api/v1/authentication/factor/cancel", "review-status": "/api/v1/authentication/login-review/status", "review-complete": "/api/v1/authentication/login-review/complete", "mfa-setup": "/api/v1/authentication/mfa/setup/confirm"}
	path, ok := routes[step]
	if !ok {
		return out, errors.New("invalid authentication step")
	}
	payload := map[string]string{}
	switch step {
	case "password-complete":
		payload = map[string]string{"change_token": in.ChangeToken, "new_password": in.NewPassword}
	case "password-status", "password-cancel":
		payload = map[string]string{"change_token": in.ChangeToken}
	case "login":
		payload = map[string]string{"username": in.Username, "password": in.Password, "otp": in.OTP}
	case "radius-login":
		payload = map[string]string{"username": in.Username, "password": in.Password}
	case "radius-challenge":
		payload = map[string]string{"challenge_token": in.ChallengeToken, "response": in.Response}
	case "radius-complete":
		payload = map[string]string{"pending_token": in.PendingToken, "otp": in.OTP, "setup_token": in.SetupToken}
	case "factor-complete":
		payload = map[string]string{"factor_token": in.FactorToken, "response": in.Response}
	case "factor-cancel":
		payload = map[string]string{"factor_token": in.FactorToken}
	case "review-status", "review-complete":
		payload = map[string]string{"review_token": in.ReviewToken}
	case "mfa-setup":
		payload = map[string]string{"setup_token": in.SetupToken, "otp": in.OTP}
	}
	raw, e := json.Marshal(payload)
	if e != nil || len(raw) > 16384 {
		return out, errors.New("invalid authentication input")
	}
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	request, e := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(raw))
	if e != nil {
		return out, e
	}
	request.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(request)
	if e != nil {
		return out, errors.New("platform authentication request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == 204 {
		return out, nil
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 || json.Unmarshal(body, &out) != nil {
		return out, errors.New("invalid authentication response")
	}
	if response.StatusCode == 401 && (out.MFARequired || out.MFASetupRequired) {
		return out, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return AuthenticationResult{}, fmt.Errorf("platform authentication rejected (%d)", response.StatusCode)
	}
	if out.PasswordChangeRequired && (step != "password-status" && out.ChangeToken == "" || out.AccessToken != "" || out.ChangeToken != "" && len(out.ChangeToken) > 128 || out.ExpiresAt.IsZero()) || out.PasswordChanged && out.AccessToken != "" {
		return AuthenticationResult{}, errors.New("invalid restricted password response")
	}
	if out.AccessToken != "" && (len(out.AccessToken) > 128 || out.User == nil || out.ExpiresAt.IsZero()) {
		return AuthenticationResult{}, errors.New("invalid platform session response")
	}
	return out, nil
}
func (c *Client) RadiusSettings(ctx context.Context) (RadiusSettings, error) {
	var out RadiusSettings
	e := c.jobRequest(ctx, "GET", "/api/v1/settings/security/radius", nil, &out)
	return out, e
}
func (c *Client) SaveRadiusSettings(ctx context.Context, in RadiusSettingsInput) (RadiusSettings, error) {
	var out RadiusSettings
	e := c.jobRequest(ctx, "PUT", "/api/v1/settings/security/radius", in, &out)
	return out, e
}
func (c *Client) RadiusAudit(ctx context.Context, offset, limit int) (RadiusAuditPage, error) {
	var out RadiusAuditPage
	q, e := operationPage(offset, limit)
	if e != nil {
		return out, e
	}
	e = c.jobRequest(ctx, "GET", "/api/v1/settings/security/radius/audit"+q, nil, &out)
	return out, e
}
func (c *Client) ProbeRadius(ctx context.Context, endpoint, username, password string) (int, error) {
	var out struct {
		Result int `json:"result"`
	}
	if endpoint != "primary" && endpoint != "factor" {
		return 0, errors.New("invalid RADIUS probe endpoint")
	}
	e := c.jobRequest(ctx, "POST", "/api/v1/settings/security/radius/check", map[string]string{"endpoint": endpoint, "username": username, "password": password}, &out)
	return out.Result, e
}
