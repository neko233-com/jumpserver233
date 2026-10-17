package assets

import (
	"context"
	"sort"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
)

// AccessTarget inventory is metadata only. Bindings include connection settings
// and endpoint identity, but exclude credential revisions so rotation is safe.
func (s *Service) ResolveAccessTargets(ctx context.Context, selected []tickets.Target, tree []nodes.Node) ([]tickets.Prepared, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	byNode := map[string]nodes.Node{}
	for _, n := range tree {
		byNode[n.ID] = n
	}
	ancestry := func(id string) []string {
		out := []string{}
		seen := map[string]bool{}
		for id != "" && len(out) < 128 && !seen[id] {
			n, ok := byNode[id]
			if !ok {
				break
			}
			seen[id] = true
			out = append(out, id)
			id = n.ParentID
		}
		return out
	}
	out := make([]tickets.Prepared, 0, len(selected))
	for _, target := range selected {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		ref := tickets.Ref{Target: target}
		var binding any
		var ancestors []string
		if target.Kind == "node" {
			n, ok := byNode[target.ID]
			if !ok {
				return nil, tickets.ErrNotFound
			}
			ref.Name, ref.Protocol = n.Name, "node"
			ancestors = ancestry(n.ID)
			binding = struct {
				Node      nodes.Node
				Ancestors []string
			}{n, ancestors}
		} else if target.Kind == "asset" {
			parent, ok := s.store.assets[target.ID]
			if !ok || parent.ParentAssetID != "" {
				return nil, tickets.ErrNotFound
			}
			var endpoint Asset
			found := false
			for _, row := range s.store.assets {
				a := row.Asset
				if ResourceID(a) == parent.ID && a.Username == target.Account && !a.AccountDisabled && !remoteAccountPending(a) {
					if found {
						return nil, tickets.ErrConflict
					}
					endpoint = a
					found = true
				}
			}
			if !found {
				return nil, tickets.ErrNotFound
			}
			ref.Name, ref.Protocol = parent.Name, endpoint.Protocol
			if ref.Protocol == "" {
				ref.Protocol = "ssh"
			}
			ancestors = ancestry(parent.NodeID)
			// Explicit stable fields avoid including credential or rotation metadata.
			stable := func(a Asset) any {
				return struct {
					ID, Name, Host, Username, Protocol, NodeID, GatewayID, Fingerprint string
					Port                                                               int
					Settings                                                           []any
					GatewayIDs                                                         []string
				}{a.ID, a.Name, a.Host, a.Username, a.Protocol, a.NodeID, a.GatewayID, a.HostKeyFingerprint, a.Port, []any{a.RDP, a.Telnet, a.Kubernetes, a.PostgreSQL, a.MySQL, a.SQLServer, a.ClickHouse, a.Redis, a.MongoDB}, a.GatewayIDs}
			}
			route := []any{stable(endpoint)}
			seen := map[string]bool{endpoint.ID: true}
			gateway := endpoint.GatewayID
			for gateway != "" {
				a, ok := s.store.assets[gateway]
				if !ok || seen[gateway] || len(route) > 8 || a.AccountDisabled {
					return nil, tickets.ErrStale
				}
				seen[gateway] = true
				route = append(route, stable(a.Asset))
				gateway = a.GatewayID
			}
			binding = struct {
				Route     []any
				Parent    any
				Ancestors []string
			}{route, stable(parent.Asset), ancestors}
		} else {
			return nil, tickets.ErrInvalid
		}
		out = append(out, tickets.Prepared{Ref: ref, Binding: s.store.importMAC("access-ticket-binding/v1", binding), Nodes: ancestors})
	}
	return out, nil
}

func (s *Service) AccessCatalog(ctx context.Context, p tickets.Policy, tree []nodes.Node, search string, offset, limit int) (tickets.Page[tickets.Ref], error) {
	if offset < 0 || limit < 1 || limit > 100 || len(search) > 240 {
		return tickets.Page[tickets.Ref]{}, tickets.ErrInvalid
	}
	type parent struct{ name, node string }
	type accountKey struct{ asset, account string }
	type candidateKey struct{ kind, id, account string }
	type candidate struct {
		key            candidateKey
		name, protocol string
		actions        uint8
	}
	// Snapshot only public catalog fields; credential and connection structs never
	// enter this query. Materialize action slices only for the requested page.
	parents := map[string]parent{}
	accounts := map[accountKey]string{}
	s.store.mu.RLock()
	for _, row := range s.store.assets {
		a := row.Asset
		if a.ParentAssetID == "" {
			parents[a.ID] = parent{a.Name, a.NodeID}
		}
		if !a.AccountDisabled && !remoteAccountPending(a) {
			protocol := a.Protocol
			if protocol == "" {
				protocol = "ssh"
			}
			accounts[accountKey{ResourceID(a), a.Username}] = protocol
		}
	}
	s.store.mu.RUnlock()
	byNode := map[string]nodes.Node{}
	for _, n := range tree {
		byNode[n.ID] = n
	}
	descendants := map[string][]string{}
	for id, a := range parents {
		seen := map[string]bool{}
		for node := a.node; node != "" && !seen[node]; {
			seen[node] = true
			n, ok := byNode[node]
			if !ok {
				break
			}
			descendants[node] = append(descendants[node], id)
			node = n.ParentID
		}
	}
	candidates := map[candidateKey]candidate{}
	add := func(kind, id, name, protocol, account string, actions uint8) {
		k := candidateKey{kind, id, account}
		v := candidates[k]
		v.key = k
		v.name = name
		v.protocol = protocol
		v.actions |= actions
		candidates[k] = v
	}
	for _, scope := range p.Scopes {
		if e := ctx.Err(); e != nil {
			return tickets.Page[tickets.Ref]{}, e
		}
		actions := uint8(1)
		for _, a := range scope.Actions {
			switch a {
			case "connect":
				actions |= 2
			case "sftp":
				actions |= 4
			}
		}
		for _, account := range scope.Accounts {
			ids := []string{scope.ID}
			if scope.Kind == "node" {
				n, ok := byNode[scope.ID]
				if !ok {
					continue
				}
				add("node", n.ID, n.Name, "node", account, actions)
				ids = descendants[scope.ID]
			}
			for _, id := range ids {
				a, ok := parents[id]
				protocol, exists := accounts[accountKey{id, account}]
				if ok && exists {
					add("asset", id, a.name, protocol, account, actions)
				}
			}
		}
	}
	rows := make([]candidate, 0, len(candidates))
	q := strings.ToLower(search)
	for _, v := range candidates {
		if q == "" || strings.Contains(strings.ToLower(v.name+" "+v.key.account+" "+v.key.id), q) {
			rows = append(rows, v)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.key.kind != b.key.kind {
			return a.key.kind < b.key.kind
		}
		if a.key.id != b.key.id {
			return a.key.id < b.key.id
		}
		return a.key.account < b.key.account
	})
	total := len(rows)
	offset = min(offset, total)
	out := tickets.Page[tickets.Ref]{Results: []tickets.Ref{}, Total: total}
	for _, v := range rows[offset:min(total, offset+limit)] {
		actions := []string{}
		if v.actions&2 != 0 {
			actions = append(actions, "connect")
		}
		if v.actions&4 != 0 {
			actions = append(actions, "sftp")
		}
		actions = append(actions, "view")
		out.Results = append(out.Results, tickets.Ref{Target: tickets.Target{Kind: v.key.kind, ID: v.key.id, Account: v.key.account, Actions: actions}, Name: v.name, Protocol: v.protocol})
	}
	return out, nil
}
