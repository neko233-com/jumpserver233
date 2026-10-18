package assets

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"slices"
)

type monitorEndpoint struct {
	Host, User, Fingerprint string
	Port                    int
}

func monitorTargetBinding(a Asset, target sshclient.Target) string {
	route := []monitorEndpoint{{target.Host, target.Username, target.HostKeyFingerprint, target.Port}}
	for _, g := range target.Gateways {
		route = append(route, monitorEndpoint{g.Target.Host, g.Target.Username, g.Target.HostKeyFingerprint, g.Target.Port})
	}
	return eventfeed.Digest(struct {
		ID, Node, Gateway string
		Route             []monitorEndpoint
	}{a.ID, a.NodeID, a.GatewayID, route})
}

// MonitorSources reads public inventory and cached platform observations only.
// Vault credentials, remote commands/output and private connection structs do
// not leave the asset service.
func (s *Service) MonitorSources(ancestors func(string) []string) []monitoralerts.Source {
	inventory := s.store.List()
	byID := map[string]Asset{}
	for _, a := range inventory {
		byID[a.ID] = a
	}
	out := make([]monitoralerts.Source, 0, len(inventory))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range inventory {
		if !IsSSH(a) || a.ParentAssetID != "" || a.AccountDisabled {
			continue
		}
		target := sshTarget(a)
		gateways := []sshclient.Hop{}
		seen := map[string]bool{a.ID: true}
		id := a.GatewayID
		valid := true
		for id != "" {
			g, ok := byID[id]
			if !ok || seen[id] || g.AccountDisabled || !IsSSH(g) || len(gateways) >= sshclient.MaxGatewayHops {
				valid = false
				break
			}
			seen[id] = true
			gateways = append(gateways, sshclient.Hop{Target: sshTarget(g)})
			id = g.GatewayID
		}
		if !valid {
			continue
		}
		slices.Reverse(gateways)
		target.Gateways = gateways
		binding := monitorTargetBinding(a, target)
		status := s.status[a.ID]
		source := monitoralerts.Source{AssetID: a.ID, AssetName: eventfeed.MetadataText(a.Name, 480), Binding: binding, State: "unknown", Values: map[string]float64{}}
		if ancestors != nil {
			source.Nodes = ancestors(a.NodeID)
		}
		if status.LastChecked != nil && status.binding == binding {
			source.At = *status.LastChecked
			source.State = status.State
			if status.State == "online" && status.Metrics != nil {
				m := status.Metrics
				source.Values["cpu_percent"] = m.CPUPercent
				if m.MemoryTotalBytes > 0 {
					source.Values["memory_percent"] = m.MemoryPercent
				}
				if m.DiskTotalBytes > 0 {
					source.Values["disk_percent"] = m.DiskPercent
				}
				source.Values["latency_ms"] = float64(m.LatencyMillis)
				if status.networkReady {
					source.Values["network_rx_bps"] = status.NetworkReceivedBytesPerSecond
					source.Values["network_tx_bps"] = status.NetworkSentBytesPerSecond
				}
			}
		}
		out = append(out, source)
	}
	return out
}
