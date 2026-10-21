// Package originpolicy validates canonical browser origins without DNS resolution.
package originpolicy

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func parse(value string) (*url.URL, bool) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, false
		}
	}
	return u, true
}

func localHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && (ip.IsLoopback() || ip.IsPrivate())
}

// ValidPublic permits HTTPS and explicitly configured loopback/private-IP HTTP.
func ValidPublic(value string) bool {
	u, ok := parse(value)
	return ok && (u.Scheme == "https" || localHost(u.Hostname()))
}

// SameLocal permits a same-origin standalone request to a literal private IP or
// loopback host. Unconfigured DNS names cannot become trusted through rebinding.
func SameLocal(origin, requestHost string, tls bool) bool {
	u, ok := parse(origin)
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return ok && u.Scheme == scheme && u.Host == requestHost && localHost(u.Hostname())
}
