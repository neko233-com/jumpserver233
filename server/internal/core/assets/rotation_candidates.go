package assets

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"sort"
	"strings"
)

// RotationCandidates returns metadata from this organization only.
func (s *Service) RotationCandidates(q, collectorFor string, offset, limit int) ([]rotationplans.Ref, int, error) {
	if len(q) > 128 || offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalidInput
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	var target Asset
	if collectorFor != "" {
		r, ok := s.store.assets[collectorFor]
		if !ok || !SupportsPasswordRotation(r.Asset) || credentialType(r.CredentialType) != CredentialPassword {
			return nil, 0, ErrNotFound
		}
		target = r.Asset
	}
	items := []rotationplans.Ref{}
	search := strings.ToLower(q)
	for _, r := range s.store.assets {
		a := r.Asset
		if !ManagedAccountsSupported(a) || collectorFor == "" && !SupportsPasswordRotation(a) || a.AccountDisabled || remoteAccountPending(a) {
			continue
		}
		if collectorFor != "" && (a.ID == collectorFor || !sameRotationHost(a, target)) {
			continue
		}
		parent := s.store.assets[ResourceID(a)]
		if search != "" && !strings.Contains(strings.ToLower(parent.Name+" "+a.Username+" "+a.ID), search) {
			continue
		}
		ref := rotationplans.Ref{AssetID: ResourceID(a), AccountID: a.ID, AssetName: parent.Name, Username: a.Username, CredentialType: credentialType(a.CredentialType)}
		if !IsSSH(a) {
			ref.Protocol = Protocol(a)
		}
		if a.PAM != nil {
			ref.Platform = a.PAM.Platform
			ref.AccountHost = a.PAM.Principal.Host
		}
		items = append(items, ref)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].AssetName != items[j].AssetName {
			return items[i].AssetName < items[j].AssetName
		}
		if items[i].Username != items[j].Username {
			return items[i].Username < items[j].Username
		}
		return items[i].AccountID < items[j].AccountID
	})
	total := len(items)
	offset = min(offset, total)
	return items[offset:min(total, offset+limit)], total, nil
}
