package assetdiscovery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
)

func (s *Service) Preview(ctx context.Context, in PreviewInput, actor Actor) (Preview, error) {
	if !validActor(actor) || len(in.Findings) == 0 || len(in.Findings) > MaxImportRows {
		return Preview{}, ErrInvalid
	}
	source, e := s.store.source(in.SourceID)
	if e != nil {
		return Preview{}, e
	}
	if e = s.authorize(ctx, actor, publicSource(source), "import"); e != nil {
		return Preview{}, e
	}
	if e = s.ValidateSnapshot(in.SourceID, in.SourceRevision, in.PolicyID, in.PolicyRevision); e != nil {
		return Preview{}, e
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e = s.store.refreshLocked(); e != nil {
		return Preview{}, e
	}
	current, e := sourceFrom(s.store.data, in.SourceID)
	if e != nil || current.Input.Revision != in.SourceRevision {
		return Preview{}, ErrConflict
	}
	policy, ok := s.store.data.Policies[in.PolicyID]
	if !ok || !policy.Enabled || policy.SourceID != in.SourceID || policy.Revision != in.PolicyRevision {
		return Preview{}, ErrConflict
	}
	seen := map[string]bool{}
	planned := []Finding{}
	for _, selection := range in.Findings {
		f, ok := s.store.data.Findings[selection.ID]
		if !ok || f.SourceID != in.SourceID || f.SourceRevision != in.SourceRevision || f.Revision != selection.Revision || seen[f.ID] || !eligible(f) || !matchPolicy(policy, f.Host) {
			return Preview{}, ErrConflict
		}
		if f.Protocol == "ssh" && (selection.HostKeyFingerprint == "" || selection.HostKeyFingerprint != f.HostKeyFingerprint) {
			return Preview{}, ErrPreview
		}
		seen[f.ID] = true
		planned = append(planned, f)
	}
	sort.Slice(planned, func(i, j int) bool { return planned[i].ID < planned[j].ID })
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return Preview{}, e
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	expires := s.now().Add(5 * time.Minute)
	next := copyJSON(s.store.data)
	for hash, p := range next.Previews {
		if !p.ExpiresAt.After(s.now()) {
			delete(next.Previews, hash)
		}
	}
	if len(next.Previews) >= 128 {
		return Preview{}, ErrCapacity
	}
	next.Previews[s.store.hash(token)] = previewRecord{Actor: actor, Input: copyJSON(in), ExpiresAt: expires, Planned: planned}
	if e = s.store.saveLocked(next); e != nil {
		return Preview{}, e
	}
	return Preview{Token: token, ExpiresAt: expires, Results: planned}, nil
}
func (s *Service) Import(ctx context.Context, in ImportInput, actor Actor) (ImportResult, error) {
	if !validActor(actor) || !requestPattern.MatchString(in.RequestID) || len(in.Token) != 43 {
		return ImportResult{}, ErrInvalid
	}
	owned, done, trackError := s.trackImport(ctx)
	if trackError != nil {
		return ImportResult{}, trackError
	}
	defer done()
	ctx = owned
	// Serialize commits in one runtime; persisted claims and deterministic asset
	// identities provide retry/takeover safety across process lifetimes.
	s.importMu.Lock()
	defer s.importMu.Unlock()
	if e := ctx.Err(); e != nil {
		return ImportResult{}, e
	}
	tokenHash := s.store.hash(in.Token)
	requestHash := s.store.hash("import\x00" + actor.ID + "\x00" + in.RequestID)
	s.store.mu.Lock()
	if e := s.store.refreshLocked(); e != nil {
		s.store.mu.Unlock()
		return ImportResult{}, e
	}
	receipt, exists := s.store.data.Receipts[requestHash]
	if exists && receipt.TokenHash != tokenHash {
		s.store.mu.Unlock()
		return ImportResult{}, ErrConflict
	}
	preview, ok := s.store.data.Previews[tokenHash]
	if !exists && (!ok || preview.Used || !preview.ExpiresAt.After(s.now()) || preview.Actor.ID != actor.ID) {
		s.store.mu.Unlock()
		return ImportResult{}, ErrPreview
	}
	input := preview.Input
	if exists {
		input = receipt.Input
	}
	source, e := sourceFrom(s.store.data, input.SourceID)
	s.store.mu.Unlock()
	if e != nil {
		return ImportResult{}, e
	}
	if e = s.authorize(ctx, actor, publicSource(source), "import"); e != nil {
		return ImportResult{}, e
	}
	if exists && receipt.Result != nil {
		return copyJSON(*receipt.Result), nil
	}
	if e = s.ValidateSnapshot(input.SourceID, input.SourceRevision, input.PolicyID, input.PolicyRevision); e != nil {
		return ImportResult{}, e
	}
	policy, e := s.store.Policy(input.PolicyID)
	if e != nil {
		return ImportResult{}, e
	}
	if !exists {
		s.store.mu.Lock()
		if e = s.store.refreshLocked(); e != nil {
			s.store.mu.Unlock()
			return ImportResult{}, e
		}
		preview, ok = s.store.data.Previews[tokenHash]
		if !ok || preview.Used || !preview.ExpiresAt.After(s.now()) || preview.Actor.ID != actor.ID {
			s.store.mu.Unlock()
			return ImportResult{}, ErrPreview
		}
		for _, selected := range input.Findings {
			f, ok := s.store.data.Findings[selected.ID]
			if !ok || f.Revision != selected.Revision || f.SourceRevision != input.SourceRevision {
				s.store.mu.Unlock()
				return ImportResult{}, ErrConflict
			}
		}
		next := copyJSON(s.store.data)
		if len(next.Receipts) >= 200 {
			oldest := ""
			for hash, r := range next.Receipts {
				if r.Result != nil && (oldest == "" || r.At.Before(next.Receipts[oldest].At)) {
					oldest = hash
				}
			}
			if oldest == "" {
				s.store.mu.Unlock()
				return ImportResult{}, ErrCapacity
			}
			delete(next.Receipts, oldest)
		}
		preview.Used = true
		preview.RequestHash = requestHash
		next.Previews[tokenHash] = preview
		receipt = receiptRecord{Actor: actor, SourceID: input.SourceID, TokenHash: tokenHash, Input: input, Planned: copyJSON(preview.Planned), At: s.now()}
		next.Receipts[requestHash] = receipt
		preview.Planned = nil
		preview.Input.Findings = nil
		next.Previews[tokenHash] = preview
		audit(&next, Audit{At: s.now(), Actor: actor, Action: "import_claimed", SourceID: input.SourceID, PolicyID: input.PolicyID, Count: len(receipt.Planned)})
		e = s.store.saveLocked(next)
		s.store.mu.Unlock()
		if e != nil {
			return ImportResult{}, e
		}
	}
	result := ImportResult{RequestID: in.RequestID, Results: []Finding{}}
	synced, e := s.applyRows(ctx, receipt.Actor, source, policy, receipt.Planned, make([]bool, len(receipt.Planned)))
	if e != nil {
		return ImportResult{}, e
	}
	for i, f := range synced {
		result.Results = append(result.Results, f)
		if f.SyncError != "" {
			continue
		}
		if receipt.Planned[i].AssetID == "" && f.AssetID == assets.DiscoveryAssetID(source.ID, f.ID) {
			result.Imported++
		} else if f.SyncState == "updated" {
			result.Updated++
		}
	}

	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e = s.store.refreshLocked(); e != nil {
		return ImportResult{}, e
	}
	current, ok := s.store.data.Receipts[requestHash]
	if !ok || current.Actor.ID != actor.ID || current.TokenHash != tokenHash {
		return ImportResult{}, ErrConflict
	}
	if current.Result != nil {
		return copyJSON(*current.Result), nil
	}
	next := copyJSON(s.store.data)
	current.Result = &result
	current.Planned = nil
	current.Input.Findings = nil
	next.Receipts[requestHash] = current
	for _, f := range result.Results {
		old, ok := next.Findings[f.ID]
		if ok && old.Revision == f.Revision && f.SyncError == "" {
			old.AssetID = f.AssetID
			old.SyncState = f.SyncState
			old.SyncError = ""
			old.Revision++
			next.Findings[f.ID] = old
		}
	}
	audit(&next, Audit{At: s.now(), Actor: receipt.Actor, Action: "import_finished", SourceID: source.ID, PolicyID: policy.ID, Count: result.Imported + result.Updated})
	if e = s.store.saveLocked(next); e != nil {
		return ImportResult{}, e
	}
	return copyJSON(result), nil
}

func ErrorCode(e error) string {
	switch {
	case errors.Is(e, ErrInvalid), errors.Is(e, assets.ErrInvalidInput):
		return "discovery_invalid"
	case errors.Is(e, ErrConflict), errors.Is(e, assets.ErrCredentialChanged):
		return "discovery_conflict"
	case errors.Is(e, ErrCapacity):
		return "discovery_capacity"
	case errors.Is(e, ErrNotFound), errors.Is(e, assets.ErrNotFound):
		return "discovery_not_found"
	case errors.Is(e, ErrDenied):
		return "discovery_permission_denied"
	case errors.Is(e, ErrPreview):
		return "discovery_preview_invalid"
	default:
		return "discovery_unavailable"
	}
}
