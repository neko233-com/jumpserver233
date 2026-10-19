package assets

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

type DiscoverySyncRow struct {
	FindingID       string
	Input           Input
	Update, Missing bool
	Options         DiscoverySyncOptions
}
type DiscoverySyncResult struct {
	Asset Asset
	State string
	Err   error
}

// SyncDiscoveryBatch stages at most 500 rows and persists the inventory once.
// Readers see the entire transaction; uncertain acknowledgements are reconciled
// against the authoritative store before a retry can mutate anything else.
func (s *Service) SyncDiscoveryBatch(ctx context.Context, source string, rows []DiscoverySyncRow, now time.Time) ([]DiscoverySyncResult, error) {
	if len(rows) == 0 || len(rows) > 500 {
		return nil, ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.FindingID] {
			return nil, ErrInvalidInput
		}
		seen[r.FindingID] = true
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshDiscoveryLocked(); e != nil {
		return nil, e
	}
	original := s.store.assets
	staged := make(map[string]storedAsset, len(original)+len(rows))
	// Sync only replaces records and materialized Asset values; encrypted blobs,
	// account audits and pending intents are immutable in this private transaction.
	for id, r := range original {
		r.Asset = cloneAsset(r.Asset)
		staged[id] = r
	}
	private := &Store{aead: s.store.aead, importKey: s.store.importKey, assets: staged, discoveryStaging: true}
	worker := NewService(private, nil)
	out := make([]DiscoverySyncResult, len(rows))
	prepared := []importPrepared{}
	for i, row := range rows {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		a, state, e := worker.SyncDiscovery(source, row.FindingID, row.Input, row.Update, row.Missing, now, row.Options)
		out[i] = DiscoverySyncResult{a, state, e}
		if e == nil && state == "created" {
			_, _, credential, ce := inputCredential(row.Input, nil)
			if ce != nil {
				return nil, ce
			}
			prepared = append(prepared, importPrepared{asset: a, replacement: credential})
		}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	// The coordinator is held before either store. This checks all final aliases,
	// including accounts in other organizations, in one pass.
	if e := s.validateAccountImportAliasesLocked(prepared); e != nil {
		return nil, e
	}
	s.store.assets = private.assets
	rollback := func() { s.store.assets = original }
	if e := s.store.materializeAccountsLocked(); e != nil {
		rollback()
		return nil, e
	}
	if e := s.store.validateGatewaysLocked(); e != nil {
		rollback()
		return nil, e
	}
	if discoveryMapDigest(original) == discoveryMapDigest(s.store.assets) {
		return out, nil
	}
	desired := discoveryMapDigest(s.store.assets)
	if e := s.store.persistDiscoveryLocked(); e != nil {
		if !s.store.discoveryUncertain && discoveryMapDigest(s.store.assets) == desired {
			return out, nil
		}
		if s.store.discoveryUncertain {
			rollback()
		}
		return nil, e
	}
	return out, nil
}
func discoveryMapDigest(v map[string]storedAsset) [32]byte {
	raw, _ := json.Marshal(v)
	return sha256.Sum256(raw)
}
