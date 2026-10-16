package hostagent

import (
	"encoding/json"
	"net/netip"
	"reflect"
)

// Healthy verifies both packet scope and every active persisted ban. An atomic
// BanHack state snapshot can lag a newly added kernel entry, which is harmless;
// existing kernel bans are never removed while the daemon is running.
func (p Plan) Healthy(raw []byte) bool {
	if len(raw) > MaxStateBytes || validateJSON(raw) != nil {
		return false
	}
	var v struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	sets := map[string]bool{}
	entries := map[netip.Addr]bool{}
	rules := map[string]int{}
	chains := 0
	for _, item := range v.NFTables {
		if body, ok := item["set"]; ok {
			var s struct {
				Family, Table, Name, Type string
				Elem                      []json.RawMessage
				Flags                     []string
			}
			if json.Unmarshal(body, &s) != nil || s.Family != "inet" || s.Table != "banhack233" || s.Name != "blocked" && s.Name != "blocked6" || s.Name == "blocked" && s.Type != "ipv4_addr" || s.Name == "blocked6" && s.Type != "ipv6_addr" {
				return false
			}
			if len(s.Flags) != 1 || s.Flags[0] != "timeout" || sets[s.Name] {
				return false
			}
			sets[s.Name] = true
			for _, elem := range s.Elem {
				var address string
				if json.Unmarshal(elem, &address) != nil {
					var e struct{ Elem struct{ Val string } }
					if json.Unmarshal(elem, &e) != nil {
						return false
					}
					address = e.Elem.Val
				}
				a, e := netip.ParseAddr(address)
				if e != nil || a.Is4() != (s.Name == "blocked") {
					return false
				}
				entries[a.Unmap()] = true
			}
		}
		if body, ok := item["chain"]; ok {
			var c struct {
				Family, Table, Name, Type, Hook, Policy string
				Prio                                    int
			}
			if json.Unmarshal(body, &c) != nil || c.Family != "inet" || c.Table != "banhack233" || c.Name != "input" || c.Type != "filter" || c.Hook != "input" || c.Policy != "accept" || c.Prio != -100 {
				return false
			}
			chains++
		}
		if body, ok := item["rule"]; ok {
			var r struct {
				Family, Table, Chain string
				Expr                 []any
			}
			if json.Unmarshal(body, &r) != nil || r.Family != "inet" || r.Table != "banhack233" || r.Chain != "input" {
				return false
			}
			found := false
			for _, ip := range []string{"ip", "ip6"} {
				if reflect.DeepEqual(r.Expr, p.expressions(ip)) {
					rules[ip]++
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	if !sets["blocked"] || !sets["blocked6"] || chains != 1 || rules["ip"] != 1 || rules["ip6"] != 1 {
		return false
	}
	for _, ban := range p.Bans {
		if !entries[ban.Address] {
			return false
		}
	}
	return true
}

func (p Plan) expressions(ip string) []any {
	set := "@blocked"
	if ip == "ip6" {
		set = "@blocked6"
	}
	var ports any = float64(p.Ports[0])
	if len(p.Ports) > 1 {
		values := make([]any, len(p.Ports))
		for i, v := range p.Ports {
			values[i] = float64(v)
		}
		ports = map[string]any{"set": values}
	}
	match := func(protocol, field string, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right}}
	}
	return []any{match(ip, "saddr", set), match("tcp", "dport", ports), map[string]any{"drop": nil}}
}
