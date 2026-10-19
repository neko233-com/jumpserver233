package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"slices"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
)

func (s *Service) SetMonitorHistory(history *monitorhistory.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.monitorHistory = history
}
func (s *Service) CloseMonitorHistory() {
	if h := s.historyStore(); h != nil {
		h.Close()
	}
}
func (s *Service) historyStore() *monitorhistory.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.monitorHistory
}
func (s *Service) recordHistory(id string, status MonitorStatus) {
	history := s.historyStore()
	if history == nil || status.LastChecked == nil || status.binding == "" {
		return
	}
	a, exists := s.find(id)
	if !exists || a.ParentAssetID != "" || !IsSSH(a) {
		return
	}
	p := monitorhistory.Sample{At: *status.LastChecked, Binding: status.binding, State: status.State, Values: map[string]float64{}}
	if status.State == "online" && status.Metrics != nil {
		m := status.Metrics
		p.Values["cpu_percent"] = m.CPUPercent
		if m.MemoryTotalBytes > 0 {
			p.Values["memory_percent"] = m.MemoryPercent
		}
		if m.DiskTotalBytes > 0 {
			p.Values["disk_percent"] = m.DiskPercent
		}
		p.Values["latency_ms"] = float64(m.LatencyMillis)
		if status.networkReady {
			p.Values["network_rx_bps"] = status.NetworkReceivedBytesPerSecond
			p.Values["network_tx_bps"] = status.NetworkSentBytesPerSecond
		}
	}
	// Probe truth remains independent of persistence. History exposes failures
	// through its health response; a storage failure must never fake host downtime.
	_, _ = history.Record(id, p)
}
func (s *Service) pruneHistory() {
	if h := s.historyStore(); h != nil {
		_ = h.Prune(false)
	}
}
func (s *Service) MonitorHistory(id string, from, to time.Time, step int) (monitorhistory.Page, error) {
	return s.MonitorHistoryContext(context.Background(), id, from, to, step)
}
func (s *Service) MonitorHistoryContext(ctx context.Context, id string, from, to time.Time, step int) (monitorhistory.Page, error) {
	h := s.historyStore()
	if h == nil {
		return monitorhistory.Page{}, monitorhistory.ErrClosed
	}
	byID := map[string]Asset{}
	for _, a := range s.store.List() {
		byID[a.ID] = a
	}
	a, ok := byID[id]
	if !ok || !IsSSH(a) || a.ParentAssetID != "" {
		return monitorhistory.Page{}, ErrNotFound
	}
	target, ok := monitorTargetForInventory(a, byID, true)
	if !ok {
		return monitorhistory.Page{}, ErrNotFound
	}
	return h.QueryContext(ctx, id, monitorTargetBinding(a, target), from, to, step)
}

func monitorTargetForInventory(a Asset, byID map[string]Asset, includeDisabled bool) (sshclient.Target, bool) {
	if !includeDisabled && a.AccountDisabled {
		return sshclient.Target{}, false
	}
	target := sshTarget(a)
	gateways := []sshclient.Hop{}
	seen := map[string]bool{a.ID: true}
	id := a.GatewayID
	for id != "" {
		g, ok := byID[id]
		if !ok || seen[id] || !includeDisabled && g.AccountDisabled || !IsSSH(g) || len(gateways) >= sshclient.MaxGatewayHops {
			return sshclient.Target{}, false
		}
		seen[id] = true
		gateways = append(gateways, sshclient.Hop{Target: sshTarget(g)})
		id = g.GatewayID
	}
	slices.Reverse(gateways)
	target.Gateways = gateways
	return target, true
}
