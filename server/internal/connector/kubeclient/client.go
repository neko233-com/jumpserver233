// Package kubeclient connects to an explicitly configured Kubernetes API. It
// never loads kubeconfig, ambient credentials, exec plugins or proxy settings.
package kubeclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
)

var ErrInvalid = errors.New("invalid Kubernetes configuration or target")
var ErrUnavailable = errors.New("Kubernetes request failed")
var ErrScope = errors.New("Kubernetes target is outside the configured scope")
var label = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
var podName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)

type Settings struct {
	Namespaces []string `json:"namespaces"`
	Shell      []string `json:"shell"`
	ServerName string   `json:"server_name,omitempty"`
	RootCAPEM  string   `json:"root_ca_pem,omitempty"`
}
type Target struct {
	Host string
	Port int
	Settings
	Gateways []sshclient.Hop
}
type Selection struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}
type Pod struct {
	Name       string   `json:"name"`
	UID        string   `json:"uid"`
	Containers []string `json:"containers"`
}
type ClusterError struct{ Status int }

func (e *ClusterError) Error() string {
	return "Kubernetes request failed (HTTP " + strconv.Itoa(e.Status) + ")"
}
func (e *ClusterError) Unwrap() error { return ErrUnavailable }

func Normalize(s Settings) (Settings, error) {
	s.Namespaces = append([]string(nil), s.Namespaces...)
	s.Shell = append([]string(nil), s.Shell...)
	if len(s.Namespaces) == 0 {
		s.Namespaces = []string{"default"}
	}
	if len(s.Shell) == 0 {
		s.Shell = []string{"/bin/sh"}
	}
	if len(s.Namespaces) > 64 || len(s.Shell) > 8 || len(s.ServerName) > 253 || strings.ContainsAny(s.ServerName, "/\\@ \t\r\n") || len(s.RootCAPEM) > 65536 {
		return Settings{}, ErrInvalid
	}
	slices.Sort(s.Namespaces)
	for i, n := range s.Namespaces {
		if len(n) > 63 || !label.MatchString(n) || i > 0 && n == s.Namespaces[i-1] {
			return Settings{}, ErrInvalid
		}
	}
	for _, v := range s.Shell {
		if v == "" || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return Settings{}, ErrInvalid
		}
	}
	if s.RootCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.RootCAPEM)) {
		return Settings{}, ErrInvalid
	}
	return s, nil
}
func ValidateSelection(s Settings, v Selection) error {
	if !slices.Contains(s.Namespaces, v.Namespace) {
		return ErrScope
	}
	if len(v.Pod) > 253 || !podName.MatchString(v.Pod) || v.Container != "" && (len(v.Container) > 63 || !label.MatchString(v.Container)) {
		return ErrInvalid
	}
	return nil
}
func transport(t Target) (*http.Transport, error) {
	if _, e := Normalize(t.Settings); e != nil {
		return nil, e
	}
	if t.Host == "" || len(t.Host) > 253 || strings.ContainsAny(t.Host, "/\\@ \t\r\n") || t.Port < 1 || t.Port > 65535 {
		return nil, ErrInvalid
	}
	name := t.ServerName
	if name == "" {
		name = t.Host
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if t.RootCAPEM != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
			return nil, ErrInvalid
		}
		tc.RootCAs = pool
	}
	address := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	return &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: tc, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 32768, MaxIdleConnsPerHost: 2, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != address {
			return nil, ErrScope
		}
		return sshclient.DialTunnel(ctx, t.Gateways, address, 5*time.Second)
	}}, nil
}
func endpoint(t Target, path string) string {
	return (&url.URL{Scheme: "https", Host: net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), Path: path}).String()
}
func noRedirect(*http.Request, []*http.Request) error {
	return errors.New("Kubernetes redirects are not permitted")
}
func ValidToken(token string) bool {
	return token != "" && len(token) <= 4096 && !strings.ContainsAny(token, "\r\n\x00 \t")
}
func get(ctx context.Context, t Target, token, path string, query url.Values, out any) error {
	if !ValidToken(token) {
		return ErrInvalid
	}
	tr, e := transport(t)
	if e != nil {
		return e
	}
	defer tr.CloseIdleConnections()
	u := endpoint(t, path)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if e != nil {
		return ErrInvalid
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: tr, CheckRedirect: noRedirect, Timeout: 12 * time.Second}
	r, e := client.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return &ClusterError{r.StatusCode}
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
	if e != nil || len(raw) > 4*1024*1024 {
		return ErrUnavailable
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrUnavailable
	}
	return nil
}

type nativePod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name string `json:"name"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name  string `json:"name"`
			State struct {
				Running *json.RawMessage `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (p nativePod) visible(namespace string) (Pod, bool) {
	out := Pod{Name: p.Metadata.Name, UID: p.Metadata.UID, Containers: []string{}}
	if p.Metadata.Namespace != namespace || p.Status.Phase != "Running" || len(out.UID) > 128 || len(out.Name) > 253 || !podName.MatchString(out.Name) {
		return out, false
	}
	for _, c := range p.Spec.Containers {
		if len(out.Containers) >= 64 {
			break
		}
		if len(c.Name) > 63 || !label.MatchString(c.Name) {
			continue
		}
		for _, state := range p.Status.ContainerStatuses {
			if state.Name == c.Name && state.State.Running != nil {
				out.Containers = append(out.Containers, c.Name)
				break
			}
		}
	}
	return out, len(out.Containers) > 0
}
func ListPods(ctx context.Context, t Target, token, namespace string) ([]Pod, error) {
	if !slices.Contains(t.Namespaces, namespace) {
		return nil, ErrScope
	}
	out := []Pod{}
	continuation := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		var list struct {
			Items    []nativePod `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		q := url.Values{"limit": {"200"}, "fieldSelector": {"status.phase=Running"}}
		if continuation != "" {
			q.Set("continue", continuation)
		}
		if e := get(ctx, t, token, "/api/v1/namespaces/"+namespace+"/pods", q, &list); e != nil {
			return nil, e
		}
		for _, p := range list.Items {
			if v, ok := p.visible(namespace); ok && !seen[v.Name] {
				out = append(out, v)
				seen[v.Name] = true
				if len(out) > 1000 {
					return nil, ErrUnavailable
				}
			}
		}
		continuation = list.Metadata.Continue
		if continuation == "" {
			slices.SortFunc(out, func(a, b Pod) int { return strings.Compare(a.Name, b.Name) })
			return out, nil
		}
		if len(continuation) > 4096 {
			return nil, ErrUnavailable
		}
	}
	return nil, ErrUnavailable
}
func resolve(ctx context.Context, t Target, token string, v Selection) (Selection, Pod, error) {
	if e := ValidateSelection(t.Settings, v); e != nil {
		return v, Pod{}, e
	}
	var p nativePod
	if e := get(ctx, t, token, "/api/v1/namespaces/"+v.Namespace+"/pods/"+v.Pod, nil, &p); e != nil {
		return v, Pod{}, e
	}
	visible, ok := p.visible(v.Namespace)
	if !ok || visible.Name != v.Pod {
		return v, Pod{}, ErrUnavailable
	}
	if v.Container == "" {
		v.Container = visible.Containers[0]
	}
	if !slices.Contains(visible.Containers, v.Container) {
		return v, Pod{}, ErrScope
	}
	return v, visible, nil
}
