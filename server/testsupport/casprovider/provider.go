// Package casprovider is an isolated CAS test fixture, never linked into the
// application server. It collects no user credentials.
package casprovider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Subject = "synthetic-cas-subject"

type Options struct {
	Subject, ResponseOverride string
	NotPrimary, Unavailable   bool
}
type issued struct {
	Service string
	Primary bool
	Expires time.Time
}
type Provider struct {
	BaseURL            string
	Options            Options
	ValidatedWithRenew atomic.Bool
	Validations        atomic.Int32
	mu                 sync.Mutex
	tickets            map[string]issued
}

func New(baseURL string, o Options) *Provider {
	return &Provider{BaseURL: baseURL, Options: o, tickets: map[string]issued{}}
}
func (p *Provider) Issue(service string) (string, error) {
	u, e := url.Parse(service)
	if e != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Path != "/api/v1/authentication/cas/callback" || u.Query().Get("state") == "" {
		return "", errors.New("invalid synthetic CAS service")
	}
	var raw [32]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return "", e
	}
	ticket := "ST-" + base64.RawURLEncoding.EncodeToString(raw[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.tickets {
		if time.Now().After(v.Expires) {
			delete(p.tickets, k)
		}
	}
	if len(p.tickets) >= 4096 {
		return "", errors.New("fixture full")
	}
	p.tickets[ticket] = issued{Service: service, Primary: !p.Options.NotPrimary, Expires: time.Now().Add(time.Minute)}
	return ticket, nil
}
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"base_url":%q}`, p.BaseURL)
	case "/cas/login":
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><title>Synthetic CAS provider</title><h1>Synthetic CAS identity provider</h1><p>Local test fixture only. No real credentials are collected.</p><form method="post"><button>Continue as synthetic CAS user</button></form>`))
			return
		}
		if r.Method != "POST" || r.URL.Query().Get("renew") != "true" {
			http.Error(w, "invalid fixture request", 400)
			return
		}
		service := r.URL.Query().Get("service")
		ticket, e := p.Issue(service)
		if e != nil {
			http.Error(w, "invalid fixture service", 400)
			return
		}
		u, _ := url.Parse(service)
		q := u.Query()
		q.Set("ticket", ticket)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), 303)
	case "/cas/serviceValidate", "/cas/p3/serviceValidate":
		p.Validations.Add(1)
		renew := r.URL.Query().Get("renew") == "true"
		p.ValidatedWithRenew.Store(renew)
		p.mu.Lock()
		ticket, ok := p.tickets[r.URL.Query().Get("ticket")]
		delete(p.tickets, r.URL.Query().Get("ticket"))
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		if p.Options.Unavailable {
			http.Error(w, "synthetic unavailable", 503)
			return
		}
		if !ok || ticket.Service != r.URL.Query().Get("service") || !time.Now().Before(ticket.Expires) || !renew || !ticket.Primary {
			_, _ = w.Write([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INVALID_TICKET">synthetic rejection</cas:authenticationFailure></cas:serviceResponse>`))
			return
		}
		if p.Options.ResponseOverride != "" {
			_, _ = w.Write([]byte(p.Options.ResponseOverride))
			return
		}
		subject := p.Options.Subject
		if subject == "" {
			subject = Subject
		}
		var escaped strings.Builder
		_ = xml.EscapeText(&escaped, []byte(subject))
		_, _ = fmt.Fprintf(w, `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>%s</cas:user><cas:attributes><cas:email>admin@example.invalid</cas:email><cas:roles>admin</cas:roles><cas:preferred_username>admin</cas:preferred_username></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>`, escaped.String())
	default:
		http.NotFound(w, r)
	}
}
