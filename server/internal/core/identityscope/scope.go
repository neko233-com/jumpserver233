// Package identityscope names independent identity sources without importing
// provider transports or permitting identity linking by a display attribute.
package identityscope

import (
	"net/url"
	"regexp"
	"strings"
)

const base = "/api/v1/identity-sources/"

var sourceID = regexp.MustCompile(`^idp-[a-f0-9]{32}$`)

func ValidID(id string) bool { return sourceID.MatchString(id) }
func Prefix(id string) string {
	if !ValidID(id) {
		return ""
	}
	return base + id
}
func ValidPrefix(prefix string) bool {
	return prefix == "" || strings.HasPrefix(prefix, base) && ValidID(strings.TrimPrefix(prefix, base))
}
func ID(prefix string) string {
	if !ValidPrefix(prefix) {
		return ""
	}
	return strings.TrimPrefix(prefix, base)
}

// API callbacks retain their existing suffix inside the source's namespace.
// Browser landing pages remain at the installation root with an explicit source.
func ReturnPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if strings.HasPrefix(path, "/api/") {
		return prefix + path
	}
	if path == "/login" || strings.HasPrefix(path, "/login?") {
		u, e := url.Parse(path)
		if e == nil {
			q := u.Query()
			q.Set("identity_source", ID(prefix))
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	return path
}
