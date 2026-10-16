package hostplugins

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type ProtectionPolicy struct {
	Mode                string   `json:"mode"`
	IgnoreIPs           []string `json:"ignore_ips"`
	SSHPorts            []int    `json:"ssh_ports"`
	MaxAttempts         int      `json:"max_attempts"`
	FindSeconds         int      `json:"find_seconds"`
	BanSeconds          int      `json:"ban_seconds"`
	SuccessGraceSeconds int      `json:"success_grace_seconds"`
	IntervalSeconds     int      `json:"interval_seconds"`
}

func (p ProtectionPolicy) Normalize() (ProtectionPolicy, error) {
	if p.Mode != "audit" && p.Mode != "enforce" || len(p.IgnoreIPs) > 32 || len(p.SSHPorts) > 16 {
		return p, ErrInvalid
	}
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 5
	}
	if p.FindSeconds == 0 {
		p.FindSeconds = 600
	}
	if p.BanSeconds == 0 {
		p.BanSeconds = 3600
	}
	if p.IntervalSeconds == 0 {
		p.IntervalSeconds = 10
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > 10000 || p.FindSeconds < 1 || p.FindSeconds > 86400 || p.BanSeconds < 1 || p.BanSeconds > 604800 || p.SuccessGraceSeconds < 0 || p.SuccessGraceSeconds > 86400 || p.IntervalSeconds < 1 || p.IntervalSeconds > 300 {
		return p, ErrInvalid
	}
	p.IgnoreIPs = append([]string{}, p.IgnoreIPs...)
	p.SSHPorts = append([]int{}, p.SSHPorts...)
	for i, v := range p.IgnoreIPs {
		if a, e := netip.ParseAddr(v); e == nil && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() {
			p.IgnoreIPs[i] = a.Unmap().String()
			continue
		}
		prefix, e := netip.ParsePrefix(v)
		if e != nil || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
			return p, ErrInvalid
		}
		p.IgnoreIPs[i] = prefix.Masked().String()
	}
	for _, v := range p.SSHPorts {
		if v < 1 || v > 65535 {
			return p, ErrInvalid
		}
	}
	sort.Strings(p.IgnoreIPs)
	p.IgnoreIPs = slices.Compact(p.IgnoreIPs)
	sort.Ints(p.SSHPorts)
	p.SSHPorts = slices.Compact(p.SSHPorts)
	return p, nil
}

func (p ProtectionPolicy) hash() string { b, _ := json.Marshal(p); return digest(b) }

func protectionConfig(dir string, p ProtectionPolicy) []byte {
	var v map[string]any
	_ = json.Unmarshal(managedConfig(dir), &v)
	v["dry_run"] = p.Mode != "enforce"
	v["hardening"] = map[string]any{"ssh": map[string]any{"enabled": false}}
	v["ignore_ips"] = p.IgnoreIPs
	v["ssh_ports"] = p.SSHPorts
	v["interval"] = strconv.Itoa(p.IntervalSeconds) + "s"
	v["rules"] = []any{map[string]any{"name": "ssh-auth-failure", "log_paths": []string{"/var/log/auth.log", "/var/log/secure"}, "patterns": []string{`Failed password for(?: invalid user)? (?P<user>\S+) from <HOST>`}, "reset_patterns": []string{`Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+) from <HOST>`}, "max_attempts": p.MaxAttempts, "find_time": strconv.Itoa(p.FindSeconds) + "s", "ban_time": strconv.Itoa(p.BanSeconds) + "s", "success_grace": strconv.Itoa(p.SuccessGraceSeconds) + "s", "count_by_user": true, "action": "auto"}}
	b, _ := json.Marshal(v)
	return b
}

func readPrivateJSON(ctx context.Context, h Transport, file string, limit int) (string, error) {
	q := quote(file)
	return run(ctx, h, "[ ! -L "+q+" ]; if [ -f "+q+" ]; then [ \"$(stat -c %s "+q+")\" -le "+strconv.Itoa(limit)+" ]; cat "+q+"; else printf none; fi")
}

func loadProtection(ctx context.Context, h Transport, dir, hash string) ([]byte, string, *ProtectionPolicy, error) {
	legacy := managedConfig(dir)
	if hash == digest(legacy) {
		return legacy, path.Join(dir, "config.json"), nil, nil
	}
	if !validDigest(hash) {
		return nil, "", nil, ErrIntegrity
	}
	raw, e := readPrivateJSON(ctx, h, path.Join(dir, "policy-"+hash+".json"), 8192)
	if e != nil {
		return nil, "", nil, e
	}
	if raw == "none" {
		return nil, "", nil, ErrIntegrity
	}
	var p ProtectionPolicy
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return nil, "", nil, ErrIntegrity
	}
	p, e = p.Normalize()
	if e != nil {
		return nil, "", nil, ErrIntegrity
	}
	cfg := protectionConfig(dir, p)
	if digest(cfg) != hash {
		return nil, "", nil, ErrIntegrity
	}
	return cfg, path.Join(dir, "config-"+hash+".json"), &p, nil
}

func (p ProtectionPolicy) includes(address netip.Addr) bool {
	for _, v := range p.IgnoreIPs {
		if a, e := netip.ParseAddr(v); e == nil && a.Unmap() == address.Unmap() {
			return true
		}
		if prefix, e := netip.ParsePrefix(v); e == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func protectionPeer(ctx context.Context, h Transport) (netip.Addr, int, error) {
	raw, e := run(ctx, h, "printf '%s' \"${SSH_CONNECTION:-}\"")
	parts := strings.Fields(raw)
	if e != nil || len(parts) != 4 {
		return netip.Addr{}, 0, ErrProtection
	}
	a, e := netip.ParseAddr(parts[0])
	port, pe := strconv.Atoi(parts[3])
	if e != nil || pe != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || port < 1 || port > 65535 {
		return netip.Addr{}, 0, ErrProtection
	}
	return a.Unmap(), port, nil
}

func firewallOwner(dir string) string { return "jumpserver233-" + digest([]byte(dir)) }

func firewallInspect(ctx context.Context, h Transport, dir string) (string, error) {
	raw, e := run(ctx, h, "id -u; if command -v nft >/dev/null 2>&1; then nft -j list tables; else printf unavailable; fi")
	if e != nil {
		return "", ErrProtection
	}
	parts := strings.SplitN(raw, "\n", 2)
	if len(parts) != 2 || parts[0] != "0" || parts[1] == "unavailable" {
		return "", ErrProtection
	}
	var v struct {
		NFTables []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(parts[1]), &v) != nil {
		return "", ErrProtection
	}
	for _, entry := range v.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == "banhack233" {
			// Terse output keeps ownership inspection bounded even with many bans.
			detail, readErr := run(ctx, h, "nft -j -t list table inet banhack233")
			v.NFTables = nil
			if readErr != nil || json.Unmarshal([]byte(detail), &v) != nil {
				return "", ErrProtection
			}
			for _, item := range v.NFTables {
				if item.Table != nil && item.Table.Name == "banhack233" && item.Table.Family == "inet" && item.Table.Comment == firewallOwner(dir) {
					return "owned", nil
				}
			}
			// nft 1.0.6 omits table comments from JSON. Its textual output
			// retains the top-level comment; nested rule comments are rejected.
			text, readErr := run(ctx, h, "nft -t list table inet banhack233")
			if readErr != nil {
				return "", readErr
			}
			if nftTableTextOwned(text, firewallOwner(dir)) {
				return "owned", nil
			}
			return "foreign", nil
		}
	}
	return "absent", nil
}

func nftTableTextOwned(text, owner string) bool {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "table inet banhack233 {" {
		return false
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "comment ") {
			return false
		}
		comment, e := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(line, "comment ")))
		return e == nil && comment == owner
	}
	return false
}

// The kernel table comment is the namespace ownership marker. It survives a
// process restart, while a host reboot safely recreates an empty owned table.
func firewallClaim(dir string) string {
	owner := firewallOwner(dir)
	return "[ \"$(id -u)\" = 0 ]; command -v nft >/dev/null; if nft list table inet banhack233 >/dev/null 2>&1; then " + firewallOwnershipCheck(dir) + "; else nft add table inet banhack233 " + quote("{ comment \""+owner+"\"; }") + "; fi; "
}

func firewallRemove(dir string) string {
	return "if [ \"$(id -u)\" = 0 ] && command -v nft >/dev/null 2>&1; then if " + firewallOwnershipCheck(dir) + "; then nft delete table inet banhack233; fi; fi; "
}

func firewallOwnershipCheck(dir string) string {
	return "nft -t list table inet banhack233 2>/dev/null | awk -v expected=" + quote("comment \""+firewallOwner(dir)+"\"") + " " + quote(`{sub(/^[ \t]*/,""); sub(/[ \t]*$/,""); if(NR==1){if($0!="table inet banhack233 {"){bad=1;exit};next} if($0=="")next; if($0==expected)ok=1;else bad=1;exit} END {exit !(ok && !bad)}`)
}

func protectionPreflight(ctx context.Context, h Transport, dir string, p ProtectionPolicy) error {
	peer, port, e := protectionPeer(ctx, h)
	if e != nil {
		return e
	}
	if !p.includes(peer) || !slices.Contains(p.SSHPorts, port) {
		return ErrProtection
	}
	ownership, e := firewallInspect(ctx, h, dir)
	if e != nil {
		return e
	}
	if ownership == "foreign" {
		return ErrConflict
	}
	_, e = run(ctx, h, "[ -r /var/log/auth.log ] || [ -r /var/log/secure ]")
	if e != nil {
		return ErrProtection
	}
	return nil
}

func agentLauncher(cron cronPlan, base, state, check, id string, policy *ProtectionPolicy) string {
	if policy != nil && policy.Mode == "enforce" {
		return cron.launcherScript(base, state, check, id, firewallClaim(path.Dir(cron.launcher)))
	}
	return cron.launcherScript(base, state, check, id)
}
