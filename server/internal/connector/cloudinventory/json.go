package cloudinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrPermission = errors.New("cloud inventory permission denied")

// Each attempt creates and signs a new request. No response body, credential,
// URL parameter or provider error message is included in returned errors.
func (c *Client) jsonRequest(ctx context.Context, provider string, build func() (*http.Request, error)) ([]byte, int, string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if e := ctx.Err(); e != nil {
			return nil, 0, "", e
		}
		request, e := build()
		if e != nil {
			return nil, 0, "", ErrUnavailable
		}
		response, e := c.http.Do(request)
		if e != nil {
			if ctx.Err() != nil {
				return nil, 0, "", ctx.Err()
			}
			return nil, 0, "", ErrUnavailable
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		_ = response.Body.Close()
		if e != nil || len(data) > 8<<20 {
			if ctx.Err() != nil {
				return nil, 0, "", ctx.Err()
			}
			return nil, 0, "", ErrUnavailable
		}
		retryHTTP := response.StatusCode == 429 || response.StatusCode == 500 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504
		trimmed := bytes.TrimSpace(data)
		var envelope struct {
			Code     string
			Response *struct{ Error *struct{ Code string } }
		}
		validJSON := len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &envelope) == nil
		if !validJSON && !retryHTTP {
			return nil, 0, "", ErrUnavailable
		}
		code := envelope.Code
		if provider == "tencentcloud" {
			if envelope.Response == nil && !retryHTTP {
				return nil, 0, "", ErrUnavailable
			}
			code = ""
			if envelope.Response != nil && envelope.Response.Error != nil {
				code = envelope.Response.Error.Code
				if code == "" && !retryHTTP {
					return nil, 0, "", ErrUnavailable
				}
			}
		}
		retry := retryHTTP || strings.HasPrefix(code, "Throttling") || strings.HasPrefix(code, "RequestLimitExceeded") || code == "ServiceUnavailable"
		if retry {
			if attempt == 2 {
				return nil, 0, "", ErrUnavailable
			}
			timer := time.NewTimer(time.Duration(attempt+1) * 200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, 0, "", ctx.Err()
			case <-timer.C:
			}
			continue
		}
		return data, response.StatusCode, code, nil
	}
	return nil, 0, "", ErrUnavailable
}

func providerError(status int, code string) error {
	if status == 401 || status == 403 || strings.HasPrefix(code, "AuthFailure") || strings.HasPrefix(code, "UnauthorizedOperation") || strings.HasPrefix(code, "Forbidden") || strings.HasPrefix(code, "InvalidAccessKeyId") || strings.HasPrefix(code, "SignatureDoesNotMatch") || strings.HasPrefix(code, "InvalidSecurityToken") {
		return ErrPermission
	}
	return ErrUnavailable
}

func safeCloudText(value string, limit int) bool {
	return utf8.ValidString(value) && len(value) <= limit && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
	}) < 0
}

// Preserve provider order for primary IPv4; choose a stable IPv6 when the API
// returns a set. Address values are always literal, globally-unicast IPs.
func cloudIP(values []string, ipv6 bool) (string, error) {
	seen := map[netip.Addr]bool{}
	ips := []netip.Addr{}
	for _, raw := range values {
		if raw == "" {
			continue
		}
		ip, e := netip.ParseAddr(raw)
		if e != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.Is4In6() || ipv6 != ip.Is6() {
			return "", ErrUnavailable
		}
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return "", nil
	}
	if ipv6 {
		sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })
	}
	return ips[0].String(), nil
}

func cloudTags(tags []struct{ Key, Value string }) (map[string]string, error) {
	if len(tags) > 64 {
		return nil, ErrUnavailable
	}
	out := map[string]string{}
	for _, tag := range tags {
		if tag.Key == "" || !safeCloudText(tag.Key, 512) || !safeCloudText(tag.Value, 2048) {
			return nil, ErrUnavailable
		}
		if _, exists := out[tag.Key]; exists {
			return nil, ErrUnavailable
		}
		out[tag.Key] = tag.Value
	}
	return out, nil
}

type inventoryBudget struct {
	seen  map[string]bool
	bytes int
}

func powerState(native string) string {
	switch strings.ToLower(native) {
	case "running":
		return "running"
	case "stopped", "shutdown":
		return "stopped"
	case "starting", "pending", "rebooting", "remote_reboot", "enter_rescue_mode", "rescue_mode", "exit_rescue_mode":
		return "pending"
	case "stopping", "terminating", "shutting-down":
		return "stopping"
	case "launch_failed":
		return "failed"
	default:
		return "unknown"
	}
}
func (b *inventoryBudget) add(instance Instance) error {
	if b.seen == nil {
		b.seen = map[string]bool{}
	}
	if b.seen[instance.ResourceKey()] {
		return ErrUnavailable
	}
	b.seen[instance.ResourceKey()] = true
	b.bytes += instance.EncodedSize()
	if len(b.seen) > MaxInstances || b.bytes > MaxMetadataBytes {
		return ErrCapacity
	}
	return nil
}
