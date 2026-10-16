package hostagent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testDirectory = "/root/.jumpserver233/plugins/banhack233"

func testConfig() []byte {
	b, _ := json.Marshal(map[string]any{"dry_run": false, "state_path": testDirectory + "/state.json", "ignore_ips": []string{"198.51.100.0/24", "::1"}, "ssh_ports": []int{2222, 22, 22}, "rules": []any{map[string]string{"name": "ssh-auth-failure", "action": "auto"}}})
	return b
}

func TestPlanRestoresOnlyActiveSSHAddressesWithoutExtendingExpiry(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	config := testConfig()
	bans := map[string]time.Time{"ssh-auth-failure|203.0.113.99|a": now.Add(30 * time.Second), "ssh-auth-failure|203.0.113.99|b": now.Add(40 * time.Second), "ssh-auth-failure|2001:db8::99|evil;$(x)|pipes": now.Add(20 * time.Second), "ssh-auth-failure|198.51.100.23|a": now.Add(time.Hour), "ssh-auth-failure|127.4.3.2|a": now.Add(time.Hour), "ssh-auth-failure|::ffff:127.0.0.1|a": now.Add(time.Hour), "ssh-auth-failure|192.0.2.99|a": now.Add(-time.Second)}
	state, _ := json.Marshal(map[string]any{"bans": bans, "ban_actions": map[string]string{"ssh-auth-failure|203.0.113.99|a": "nft"}})
	p, e := BuildPlan(testDirectory, SHA(config), config, state, now)
	require.NoError(t, e)
	require.Len(t, p.Bans, 2)
	require.Equal(t, []int{22, 2222}, p.Ports)
	rules := p.Rules(now.Add(5*time.Second), 123)
	require.Contains(t, rules, "delete table inet handle 123\ncreate table inet banhack233")
	require.Contains(t, rules, "203.0.113.99 timeout 35000ms")
	require.Contains(t, rules, "2001:db8::99 timeout 15000ms")
	require.Contains(t, rules, "tcp dport { 22, 2222 } drop")
	require.NotContains(t, rules, "evil")
	require.NotContains(t, rules, "198.51.100.23")
	require.NotContains(t, rules, "flush ruleset")
	require.NotContains(t, p.Rules(now.Add(time.Minute), 0), "add element")
}

func TestPlanRejectsMalformedUnboundedOrUnmanagedState(t *testing.T) {
	config := testConfig()
	now := time.Now().UTC()
	until := now.Add(time.Hour).Format(time.RFC3339Nano)
	for name, state := range map[string]string{
		"duplicate": `{"bans":{},"bans":{}}`, "null": "null", "trailing": `{} {}`,
		"invalid ip": `{"bans":{"ssh-auth-failure|x; flush ruleset":"` + until + `"}}`,
		"other rule": `{"bans":{"unknown|203.0.113.1":"` + until + `"}}`,
		"backend":    `{"bans":{"ssh-auth-failure|203.0.113.1":"` + until + `"},"ban_actions":{"ssh-auth-failure|203.0.113.1":"/bin/sh"}}`,
		"far future": `{"bans":{"ssh-auth-failure|203.0.113.1":"` + now.Add(8*24*time.Hour).Format(time.RFC3339Nano) + `"}}`,
		"depth":      `{"bans":` + strings.Repeat("[", 34) + strings.Repeat("]", 34) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, e := BuildPlan(testDirectory, SHA(config), config, []byte(state), now)
			require.ErrorIs(t, e, ErrState)
		})
	}
	_, e := BuildPlan(testDirectory, SHA(config), config, make([]byte, MaxStateBytes+1), now)
	require.ErrorIs(t, e, ErrState)
	tooMany := map[string]time.Time{}
	for i := 0; i <= MaxEntries; i++ {
		tooMany["ssh-auth-failure|203.0.113.1|"+time.Unix(int64(i), 0).Format(time.RFC3339)] = now
	}
	state, _ := json.Marshal(map[string]any{"bans": tooMany})
	_, e = BuildPlan(testDirectory, SHA(config), config, state, now)
	require.ErrorIs(t, e, ErrState)
}

func TestPlanPinsConfigHashPathsPortsAndNativeActions(t *testing.T) {
	config := testConfig()
	_, e := BuildPlan(testDirectory, strings.Repeat("0", 64), config, nil, time.Now())
	require.ErrorIs(t, e, ErrConfiguration)
	for name, mutate := range map[string]func(map[string]any){
		"dry run": func(c map[string]any) { c["dry_run"] = true }, "state path": func(c map[string]any) { c["state_path"] = "/etc/shadow" }, "port": func(c map[string]any) { c["ssh_ports"] = []int{0} }, "shell action": func(c map[string]any) {
			c["rules"] = []any{map[string]string{"name": "ssh-auth-failure", "action": "sh"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var c map[string]any
			require.NoError(t, json.Unmarshal(config, &c))
			mutate(c)
			b, _ := json.Marshal(c)
			_, e := BuildPlan(testDirectory, SHA(b), b, nil, time.Now())
			require.ErrorIs(t, e, ErrConfiguration)
		})
	}
}

func healthyJSON(t *testing.T, p Plan) []byte {
	t.Helper()
	items := []any{map[string]any{"chain": map[string]any{"family": "inet", "table": "banhack233", "name": "input", "type": "filter", "hook": "input", "prio": -100, "policy": "accept"}}}
	for _, ip := range []string{"ip", "ip6"} {
		name, kind := "blocked", "ipv4_addr"
		if ip == "ip6" {
			name, kind = "blocked6", "ipv6_addr"
		}
		var elements []any
		for _, b := range p.Bans {
			if b.Address.Is4() == (ip == "ip") {
				elements = append(elements, map[string]any{"elem": map[string]any{"val": b.Address.String(), "expires": 30000}})
			}
		}
		items = append(items, map[string]any{"set": map[string]any{"family": "inet", "table": "banhack233", "name": name, "type": kind, "flags": []string{"timeout"}, "elem": elements}}, map[string]any{"rule": map[string]any{"family": "inet", "table": "banhack233", "chain": "input", "expr": p.expressions(ip)}})
	}
	b, e := json.Marshal(map[string]any{"nftables": items})
	require.NoError(t, e)
	return b
}

func TestKernelHealthRequiresBothPacketScopeAndPersistedAddresses(t *testing.T) {
	now := time.Now().UTC()
	config := testConfig()
	state, _ := json.Marshal(map[string]any{"bans": map[string]time.Time{"ssh-auth-failure|203.0.113.99": now.Add(time.Minute), "ssh-auth-failure|2001:db8::99": now.Add(time.Minute)}})
	p, e := BuildPlan(testDirectory, SHA(config), config, state, now)
	require.NoError(t, e)
	raw := healthyJSON(t, p)
	require.True(t, p.Healthy(raw))
	for name, raw := range map[string][]byte{"missing ban": []byte(strings.ReplaceAll(string(raw), "203.0.113.99", "203.0.113.88")), "wrong port": []byte(strings.ReplaceAll(string(raw), "2222", "2223")), "all ports": []byte(strings.ReplaceAll(string(raw), `"tcp"`, `"udp"`)), "foreign chain": []byte(strings.ReplaceAll(string(raw), `"input"`, `"other"`)), "wrong priority": []byte(strings.ReplaceAll(string(raw), `"prio":-100`, `"prio":0`)), "empty": []byte(`{"nftables":[]}`)} {
		t.Run(name, func(t *testing.T) { require.False(t, p.Healthy(raw)) })
	}
	require.True(t, TableOwned("table inet banhack233 {\n\tcomment \""+p.Owner+"\"\n set blocked { }\n}", p.Owner))
	require.False(t, TableOwned("table inet banhack233 {\n chain input {\n comment \""+p.Owner+"\"\n}\n}", p.Owner))
}
