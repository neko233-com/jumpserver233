package sessionclient

import (
	"errors"
	"net"
	"net/http"
)

// LocalSupervisor refuses proxies, URL credentials, prefixes and remote origins.
// The child PID is additionally matched before any maintenance mutation.
func (c *Client) LocalSupervisor() (*Client, error) {
	u := c.serverURL
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.User != nil || u.Path != "" && u.Path != "/" {
		return nil, errors.New("supervisor requires a loopback IP origin for JMS_SERVER_URL")
	}
	v := *c
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	v.http = &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &v, nil
}
