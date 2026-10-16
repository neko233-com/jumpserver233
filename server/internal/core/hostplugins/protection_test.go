package hostplugins

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtectionPolicyNormalizationFixedActionsAndOperationSnapshots(t *testing.T) {
	p, e := (ProtectionPolicy{Mode: "enforce", IgnoreIPs: []string{"192.0.2.1", "192.0.2.1", "2001:db8::1/64"}, SSHPorts: []int{2222, 22, 22}}).Normalize()
	require.NoError(t, e)
	require.Equal(t, []int{22, 2222}, p.SSHPorts)
	require.Equal(t, []string{"192.0.2.1", "2001:db8::/64"}, p.IgnoreIPs)
	raw := protectionConfig("/home/qa/.jumpserver233/plugins/banhack233", p)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))
	require.Equal(t, false, cfg["dry_run"])
	require.Equal(t, false, cfg["hardening"].(map[string]any)["ssh"].(map[string]any)["enabled"])
	require.Equal(t, false, cfg["malware"].(map[string]any)["direct_kill"])
	require.NotContains(t, string(raw), "curl")
	require.NotContains(t, string(raw), "sudo")
	o := Operation{Plugin: "banhack233", Version: "0.2.3", Action: "protection_apply", Binding: strings.Repeat("c", 64), Protection: &p}
	require.NoError(t, o.Validate())
	require.Equal(t, "plugins.protect", o.Permission())
	require.Contains(t, o.Command(), " policy=")
	clone := o.Clone()
	clone.Protection.IgnoreIPs[0] = "198.51.100.1"
	require.NotEqual(t, o.Command(), clone.Command())
	empty, e := (ProtectionPolicy{Mode: "audit"}).Normalize()
	require.NoError(t, e)
	o.Protection = &empty
	require.NoError(t, o.Clone().Validate())
	require.Equal(t, o.Command(), o.Clone().Command())
	for _, bad := range []ProtectionPolicy{{Mode: "production"}, {Mode: "enforce", IgnoreIPs: []string{"example.com"}}, {Mode: "enforce", IgnoreIPs: []string{"127.0.0.1;id"}}, {Mode: "enforce", IgnoreIPs: []string{"fe80::1%eth0"}}, {Mode: "enforce", SSHPorts: []int{65536}}, {Mode: "audit", MaxAttempts: -1}, {Mode: "enforce", BanSeconds: 604801}} {
		_, e := bad.Normalize()
		require.ErrorIs(t, e, ErrInvalid)
	}
}

func TestReleaseSelectionPinsHistoricalVersionsAndRejectsImplicitDowngrades(t *testing.T) {
	for _, head := range Catalog() {
		old, e := LookupVersion(head.ID, head.Releases[0].Version)
		require.NoError(t, e)
		for _, a := range old.Artifacts {
			require.True(t, validDigest(a.SHA256))
			require.Contains(t, a.URL, "/v"+old.Version+"/")
		}
		require.True(t, CanUpgrade(head.ID, old.Version, head.Version))
		require.False(t, CanUpgrade(head.ID, head.Version, old.Version))
		_, e = LookupVersion(head.ID, "latest")
		require.ErrorIs(t, e, ErrInvalid)
		o := Operation{Plugin: head.ID, Version: head.Version, Action: "status", Selection: "installed", Binding: strings.Repeat("d", 64)}
		require.NoError(t, o.Validate())
		require.Contains(t, o.Command(), "version=installed catalog=")
		o.Action = "install"
		require.ErrorIs(t, o.Validate(), ErrInvalid)
	}
}

func TestNftOwnershipTextFallbackRequiresTheActualTopLevelTableComment(t *testing.T) {
	owner := "jumpserver233-test"
	require.True(t, nftTableTextOwned("table inet banhack233 {\n\tcomment \""+owner+"\"\n}", owner))
	for _, text := range []string{"table inet foreign {\n comment \"" + owner + "\"\n}", "table inet banhack233 {\n chain input {\n comment \"" + owner + "\"\n}\n}", "table inet banhack233 {\n comment \"foreign\"\n}", "table inet banhack233 {\n ip saddr 192.0.2.1 drop comment \"" + owner + "\"\n}"} {
		require.False(t, nftTableTextOwned(text, owner))
	}
}
