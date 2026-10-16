// Package casclient implements the CAS service-ticket protocol boundary.
package casclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
)

var ErrConfig = errors.New("invalid CAS configuration")
var ErrProvider = errors.New("CAS ticket validation failed")

const Namespace = "http://www.yale.edu/tp/cas"

type Config struct {
	BaseURL           string `json:"base_url"`
	Protocol          string `json:"protocol"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	CAPEM             string `json:"ca_pem"`
}
type Provider interface {
	Check(context.Context, Config) error
	Validate(context.Context, Config, string, string) (string, error)
}
type Client struct{}

func Endpoint(raw string, loopback bool) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.ForceQuery || len(raw) > 2048 {
		return false
	}
	return u.Scheme == "https" || (loopback && u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())
}
func ValidateConfig(c Config) error {
	u, e := url.Parse(c.BaseURL)
	if e != nil || !Endpoint(c.BaseURL, c.AllowLoopbackHTTP) || u.RawQuery != "" || u.RawPath != "" || (u.Path != "" && path.Clean(u.Path) != u.Path) || (c.Protocol != "2" && c.Protocol != "3") {
		return ErrConfig
	}
	_, e = tlsConfig(c)
	return e
}
func tlsConfig(c Config) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if len(c.CAPEM) > 262144 || (c.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(c.CAPEM))) {
		return nil, ErrConfig
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}
func LoginURL(c Config, service string) string {
	return c.BaseURL + "/login?" + url.Values{"service": {service}, "renew": {"true"}}.Encode()
}
func request(ctx context.Context, c Config, address string) ([]byte, error) {
	if ValidateConfig(c) != nil {
		return nil, ErrConfig
	}
	tc, _ := tlsConfig(c)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tc
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, ErrProvider
	}
	r.Header.Set("Accept", "application/xml, text/xml;q=0.9, text/html;q=0.5")
	response, e := client.Do(r)
	if e != nil {
		return nil, ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrProvider
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(body) > 1<<20 {
		return nil, ErrProvider
	}
	return body, nil
}
func (Client) Check(ctx context.Context, c Config) error {
	_, e := request(ctx, c, c.BaseURL+"/login")
	return e
}
func (Client) Validate(ctx context.Context, c Config, service, ticket string) (string, error) {
	if !strings.HasPrefix(ticket, "ST-") || len(ticket) < 4 || len(ticket) > 4096 || strings.IndexFunc(ticket, unicode.IsSpace) >= 0 || strings.IndexFunc(ticket, unicode.IsControl) >= 0 || !Endpoint(service, c.AllowLoopbackHTTP) {
		return "", ErrProvider
	}
	suffix := "/serviceValidate"
	if c.Protocol == "3" {
		suffix = "/p3/serviceValidate"
	}
	raw, e := request(ctx, c, c.BaseURL+suffix+"?"+url.Values{"service": {service}, "ticket": {ticket}, "renew": {"true"}, "format": {"XML"}}.Encode())
	if e != nil {
		return "", e
	}
	return parseResponse(raw)
}

// Parse only an unambiguous, namespaced success/user pair. Claims are ignored;
// directives, proxy credentials, duplicate outcomes, nested usernames and
// trailing documents fail closed. encoding/xml never resolves external entities.
func parseResponse(raw []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var stack []xml.Name
	var user strings.Builder
	roots, outcomes, successes, users, nodes := 0, 0, 0, 0, 0
	rootDone := false
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", ErrProvider
		}
		switch v := token.(type) {
		case xml.Directive:
			return "", ErrProvider
		case xml.ProcInst:
			if len(stack) != 0 || roots != 0 || v.Target != "xml" {
				return "", ErrProvider
			}
		case xml.StartElement:
			nodes++
			if nodes > 10000 || len(stack) >= 32 || rootDone {
				return "", ErrProvider
			}
			if len(stack) == 3 && stack[2] == (xml.Name{Space: Namespace, Local: "user"}) {
				return "", ErrProvider
			}
			depth := len(stack) + 1
			if depth == 1 {
				roots++
				if v.Name != (xml.Name{Space: Namespace, Local: "serviceResponse"}) {
					return "", ErrProvider
				}
			}
			if depth == 2 {
				outcomes++
				if v.Name == (xml.Name{Space: Namespace, Local: "authenticationSuccess"}) {
					successes++
				} else if v.Name != (xml.Name{Space: Namespace, Local: "authenticationFailure"}) {
					return "", ErrProvider
				}
			}
			if v.Name.Space == Namespace && (v.Name.Local == "proxies" || v.Name.Local == "proxyGrantingTicket") {
				return "", ErrProvider
			}
			if depth == 3 && stack[1].Local == "authenticationSuccess" && v.Name == (xml.Name{Space: Namespace, Local: "user"}) {
				users++
				if users > 1 {
					return "", ErrProvider
				}
			}
			stack = append(stack, v.Name)
		case xml.EndElement:
			if len(stack) == 0 {
				return "", ErrProvider
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootDone = true
			}
		case xml.CharData:
			if len(stack) == 3 && stack[1] == (xml.Name{Space: Namespace, Local: "authenticationSuccess"}) && stack[2] == (xml.Name{Space: Namespace, Local: "user"}) {
				if user.Len()+len(v) > 1024 {
					return "", ErrProvider
				}
				user.Write(v)
			} else if len(stack) == 0 && strings.TrimSpace(string(v)) != "" {
				return "", ErrProvider
			}
		}
	}
	subject := user.String()
	if roots != 1 || !rootDone || outcomes != 1 || successes != 1 || users != 1 || subject == "" || strings.TrimSpace(subject) != subject || strings.IndexFunc(subject, unicode.IsControl) >= 0 {
		return "", ErrProvider
	}
	return subject, nil
}
