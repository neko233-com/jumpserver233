package nativeaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/fileaccess"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

type apiClient struct {
	transport    *handlerTransport
	token        string
	organization string
	actor        string
	target       targetBinding
	execSlots    chan struct{}
}
type apiError struct {
	Status   int
	MFA      bool
	ReviewID string
}

func (e *apiError) Error() string { return "access denied or administrator review required" }
func (c *apiClient) request(ctx context.Context, method, endpoint string, body io.Reader, session string) (*http.Response, error) {
	r, e := http.NewRequestWithContext(ctx, method, apiOrigin+endpoint, body)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "JumpServer233-Native-SSH")
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.organization != "" {
		r.Header.Set("X-JMS-ORG", c.organization)
	}
	if session != "" {
		r.Header.Set("X-JMS-SFTP-Session", session)
	}
	return c.transport.client.Do(r)
}
func (c *apiClient) json(ctx context.Context, method, endpoint string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, e := c.request(ctx, method, endpoint, body, "")
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 || r.StatusCode == 202 {
		var problem struct {
			MFA      bool   `json:"mfa_required"`
			ReviewID string `json:"review_id"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&problem)
		return &apiError{Status: r.StatusCode, MFA: problem.MFA, ReviewID: problem.ReviewID}
	}
	if out == nil {
		_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 64*1024))
		return e
	}
	return json.NewDecoder(io.LimitReader(r.Body, 16*1024*1024)).Decode(out)
}
func (c *apiClient) login(ctx context.Context, username, password, otp string) error {
	var session auth.LoginSession
	e := c.json(ctx, "POST", "/api/v1/authentication/auth/", map[string]string{"username": username, "password": password, "otp": otp}, &session)
	if e != nil {
		return e
	}
	if session.AccessToken == "" {
		return errors.New("incomplete authentication")
	}
	c.token = session.AccessToken
	c.actor = session.User.Username
	if e = c.validate(ctx); e != nil {
		c.logout()
		return e
	}
	return nil
}
func (c *apiClient) validate(ctx context.Context) error {
	return c.json(ctx, "GET", "/api/v1/users/me", nil, &struct{}{})
}
func (c *apiClient) username() string { return c.actor }
func (c *apiClient) logout() {
	if c.token != "" {
		_ = c.json(context.Background(), "POST", "/api/v1/authentication/expire-session/", nil, nil)
	}
}

type authorizationResponse struct {
	headers http.Header
	status  int
}

func (w *authorizationResponse) Header() http.Header { return w.headers }
func (w *authorizationResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *authorizationResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return len(p), nil
}
func (c *apiClient) fileOperation(ctx context.Context, method, endpoint, session string, op fileaccess.Operation) error {
	r, e := http.NewRequestWithContext(fileaccess.WithOperation(ctx, op), method, apiOrigin+endpoint, nil)
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("User-Agent", "JumpServer233-Native-SFTP")
	if c.organization != "" {
		r.Header.Set("X-JMS-ORG", c.organization)
	}
	if session != "" {
		r.Header.Set("X-JMS-SFTP-Session", session)
	}
	r.RemoteAddr = c.transport.peer.String()
	w := &authorizationResponse{headers: make(http.Header)}
	c.transport.server.Handler.ServeHTTP(w, r)
	if w.status != http.StatusNoContent {
		return &apiError{Status: w.status}
	}
	return nil
}

// title and desc deliberately map to the existing name and remark fields.
// The directory uses the immutable account ID, not a user-controlled hostname.
type assetChoice struct {
	ID, Title, Desc, IP, Account string
	Connect, SFTP                bool
	Monitor                      coreassets.MonitorStatus
}

func (c *apiClient) assets(ctx context.Context) ([]assetChoice, error) {
	var rows []struct {
		ID       string                   `json:"id"`
		Name     string                   `json:"name"`
		Remark   string                   `json:"remark"`
		Host     string                   `json:"host"`
		Protocol string                   `json:"protocol"`
		Username string                   `json:"username"`
		Monitor  coreassets.MonitorStatus `json:"monitor"`
		Accounts []struct {
			ID          string   `json:"id"`
			Username    string   `json:"username"`
			Permissions []string `json:"permissions"`
			Active      bool     `json:"active"`
		} `json:"accounts"`
	}
	if e := c.json(ctx, "GET", "/api/v1/assets", nil, &rows); e != nil {
		return nil, e
	}
	out := []assetChoice{}
	for _, a := range rows {
		if a.Protocol != "" && a.Protocol != "ssh" {
			continue
		}
		for _, account := range a.Accounts {
			if !account.Active {
				continue
			}
			v := assetChoice{ID: account.ID, Title: a.Name, Desc: a.Remark, IP: a.Host, Account: account.Username, Monitor: a.Monitor}
			for _, p := range account.Permissions {
				v.Connect = v.Connect || p == "connect"
				v.SFTP = v.SFTP || p == "sftp"
			}
			if v.Connect || v.SFTP {
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if a.Account != b.Account {
			return a.Account < b.Account
		}
		return a.ID < b.ID
	})
	return out, nil
}
func filterAssets(rows []assetChoice, query string) []assetChoice {
	words := strings.Fields(strings.ToLower(query))
	out := []assetChoice{}
	for _, a := range rows {
		haystack := strings.ToLower(a.Title + "\n" + a.Desc + "\n" + a.IP + "\n" + a.Account)
		matched := true
		for _, q := range words {
			if !strings.Contains(haystack, q) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, a)
		}
	}
	return out
}
func (c *apiClient) createSession(ctx context.Context, asset string, cols, rows int) (gateway.CreatedSession, error) {
	var out gateway.CreatedSession
	e := c.json(ctx, "POST", "/api/v1/sessions", gateway.CreateRequest{AssetID: asset, Cols: cols, Rows: rows}, &out)
	return out, e
}
func (c *apiClient) closeSession(id string) {
	_ = c.json(context.Background(), "DELETE", "/api/v1/sessions/"+url.PathEscape(id), nil, nil)
}
