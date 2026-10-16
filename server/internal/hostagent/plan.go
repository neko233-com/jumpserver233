// Package hostagent implements the local, credential-free recovery component.
// It understands only platform-managed BanHack SSH policies and nftables state.
package hostagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	Version       = "3"
	MaxStateBytes = 8 << 20
	MaxEntries    = 10000
)

var (
	ErrConfiguration = errors.New("invalid_configuration")
	ErrState         = errors.New("invalid_state")
	ErrForeign       = errors.New("foreign_firewall")
	ErrKernel        = errors.New("kernel_unavailable")
	ErrBusy          = errors.New("agent_busy")
	ErrUnsupported   = errors.New("unsupported_platform")
)

type Ban struct {
	Address netip.Addr
	Until   time.Time
}

type Plan struct {
	Directory string
	ConfigSHA string
	Ports     []int
	Bans      []Ban
	Owner     string
}

func SHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// validateJSON rejects duplicates and excessive nesting before decoding maps.
// Configuration/state are bounded before this function is called.
func validateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrState
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if depth == 0 && t != json.Delim('{') {
			return ErrState
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || len(s) > 2048 || seen[s] {
					return ErrState
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrState
		}
		end, e := d.Token()
		if e != nil {
			return e
		}
		if delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return ErrState
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrState
	}
	return nil
}

func BuildPlan(directory, configSHA string, config, state []byte, now time.Time) (Plan, error) {
	p := Plan{Directory: directory, ConfigSHA: configSHA, Owner: "jumpserver233-" + SHA([]byte(directory))}
	if !path.IsAbs(directory) || path.Clean(directory) != directory || path.Base(directory) != "banhack233" || len(directory) > 2048 || strings.ContainsAny(directory, "\x00\r\n") || len(config) > 65536 || SHA(config) != configSHA || validateJSON(config) != nil {
		return p, ErrConfiguration
	}
	var c struct {
		DryRun    bool     `json:"dry_run"`
		StatePath string   `json:"state_path"`
		IgnoreIPs []string `json:"ignore_ips"`
		SSHPorts  []int    `json:"ssh_ports"`
		Rules     []struct {
			Name   string `json:"name"`
			Action string `json:"action"`
		} `json:"rules"`
	}
	if json.Unmarshal(config, &c) != nil || c.DryRun || c.StatePath != path.Join(directory, "state.json") || len(c.IgnoreIPs) > 32 || len(c.SSHPorts) == 0 || len(c.SSHPorts) > 16 || len(c.Rules) != 1 || c.Rules[0].Name != "ssh-auth-failure" || c.Rules[0].Action != "auto" {
		return p, ErrConfiguration
	}
	var ignores []netip.Prefix
	for _, s := range c.IgnoreIPs {
		if a, e := netip.ParseAddr(s); e == nil && a.Zone() == "" {
			a = a.Unmap()
			ignores = append(ignores, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		a, e := netip.ParsePrefix(s)
		if e != nil || a.Addr().Is4In6() {
			return p, ErrConfiguration
		}
		ignores = append(ignores, a.Masked())
	}
	ignored := func(a netip.Addr) bool {
		if a.IsLoopback() {
			return true
		}
		for _, prefix := range ignores {
			if prefix.Contains(a) {
				return true
			}
		}
		return false
	}
	ports := map[int]bool{}
	for _, v := range c.SSHPorts {
		if v < 1 || v > 65535 {
			return p, ErrConfiguration
		}
		ports[v] = true
	}
	for v := range ports {
		p.Ports = append(p.Ports, v)
	}
	sort.Ints(p.Ports)
	if len(state) == 0 {
		return p, nil
	}
	if len(state) > MaxStateBytes || validateJSON(state) != nil {
		return p, ErrState
	}
	var st struct {
		Bans    map[string]time.Time `json:"bans"`
		Actions map[string]string    `json:"ban_actions"`
	}
	if json.Unmarshal(state, &st) != nil || len(st.Bans) > MaxEntries {
		return p, ErrState
	}
	active := map[netip.Addr]time.Time{}
	for key, until := range st.Bans {
		parts := strings.Split(key, "|")
		if len(key) > 2048 || len(parts) < 2 || parts[0] != "ssh-auth-failure" {
			return p, ErrState
		}
		a, e := netip.ParseAddr(parts[1])
		if e != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return p, ErrState
		}
		a = a.Unmap()
		if !until.After(now) || ignored(a) {
			continue
		}
		if until.After(now.Add(7*24*time.Hour + time.Second)) {
			return p, ErrState
		}
		if action := st.Actions[key]; action != "" && action != "auto" && action != "nft" {
			return p, ErrState
		}
		if until.After(active[a]) {
			active[a] = until
		}
	}
	for a, until := range active {
		p.Bans = append(p.Bans, Ban{a, until})
	}
	sort.Slice(p.Bans, func(i, j int) bool { return p.Bans[i].Address.Compare(p.Bans[j].Address) < 0 })
	return p, nil
}

func (p Plan) Rules(now time.Time, handle uint64) string {
	var b strings.Builder
	if handle != 0 {
		fmt.Fprintf(&b, "delete table inet handle %d\n", handle)
	}
	fmt.Fprintf(&b, "create table inet banhack233 { comment %s; }\n", strconv.Quote(p.Owner))
	b.WriteString("add set inet banhack233 blocked { type ipv4_addr; flags timeout; }\nadd set inet banhack233 blocked6 { type ipv6_addr; flags timeout; }\nadd chain inet banhack233 input { type filter hook input priority -100; policy accept; }\n")
	ports := make([]string, len(p.Ports))
	for i, v := range p.Ports {
		ports[i] = strconv.Itoa(v)
	}
	expr := ports[0]
	if len(ports) > 1 {
		expr = "{ " + strings.Join(ports, ", ") + " }"
	}
	fmt.Fprintf(&b, "add rule inet banhack233 input ip saddr @blocked tcp dport %s drop\nadd rule inet banhack233 input ip6 saddr @blocked6 tcp dport %s drop\n", expr, expr)
	for _, ban := range p.Bans {
		ms := ban.Until.Sub(now).Milliseconds()
		if ms < 1 {
			continue
		}
		set := "blocked"
		if ban.Address.Is6() {
			set = "blocked6"
		}
		fmt.Fprintf(&b, "add element inet banhack233 %s { %s timeout %dms }\n", set, ban.Address.String(), ms)
	}
	return b.String()
}

func TableOwned(text, owner string) bool {
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
		s, e := strconv.Unquote(strings.TrimPrefix(line, "comment "))
		return e == nil && s == owner
	}
	return false
}
