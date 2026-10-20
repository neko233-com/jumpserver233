package assets

// InventoryStats uses only inventory IDs/protocols and already collected probe
// state. It never decrypts credentials or probes a remote machine.
type InventoryStats struct {
	Assets, SSHAssets, Online, Offline, Unknown int
	Protocols                                   map[string]int
}

func (s *Service) InventoryStats() InventoryStats {
	s.store.mu.RLock()
	protocols := make(map[string]string, len(s.store.assets))
	for id, record := range s.store.assets {
		if record.ParentAssetID == "" {
			protocols[id] = Protocol(record.Asset)
		}
	}
	s.store.mu.RUnlock()
	out := InventoryStats{Protocols: map[string]int{}}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, protocol := range protocols {
		out.Assets++
		out.Protocols[protocol]++
		if protocol == "ssh" {
			out.SSHAssets++
		}
		switch s.status[id].State {
		case "online":
			out.Online++
		case "offline":
			out.Offline++
		default:
			out.Unknown++
		}
	}
	return out
}
