package assetdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"strconv"
)

func syncError(e error) string {
	if errors.Is(e, ErrDenied) {
		return "scan_permission_revoked"
	}
	if errors.Is(e, ErrConflict) {
		return "scan_configuration_changed"
	}
	return "scan_storage_failed"
}

func discoveryInput(source sourceRecord, policy Policy, f Finding) assets.Input {
	in := copyJSON(source.Input.Template)
	in.Name = policy.NamePrefix + f.Host + "-" + strconv.Itoa(f.Port)
	if f.Cloud != nil {
		in.Name = policy.NamePrefix + f.Cloud.DisplayName(f.Port)
	}
	in.Host = f.Host
	in.Port = f.Port
	in.HostKeyFingerprint = f.HostKeyFingerprint
	in.Group = policy.Group
	in.NodeID = policy.NodeID
	gateway := source.Input.GatewayID
	in.GatewayID = &gateway
	return in
}

func AssetSyncOptions(source Source, policy Policy, finding Finding) assets.DiscoverySyncOptions {
	option := assets.DiscoverySyncOptions{PolicyID: policy.ID, Overwrite: policy.OverwriteManualChanges}
	var template struct {
		Protocol string `json:"protocol"`
	}
	if json.Unmarshal(source.Template, &template) != nil {
		return option
	}
	if cloud := finding.Cloud; cloud != nil && policy.MigrateCloudSSHAddress && policy.UpdateExisting && source.Provider != "lan" && template.Protocol == "ssh" && finding.Protocol == "ssh" && finding.SSHVerified && finding.Open && !cloud.Missing && cloud.State == "running" {
		option.MigrateCloudSSHAddress = true
		option.CloudResourceKey = cloud.ResourceKey()
	}
	return option
}
func (s *Service) applyRows(ctx context.Context, actor Actor, source sourceRecord, policy Policy, findings []Finding, missing []bool) ([]Finding, error) {
	if e := s.authorize(ctx, actor, publicSource(source), "import"); e != nil {
		return nil, e
	}
	if e := s.ValidateSnapshot(source.ID, source.Input.Revision, policy.ID, policy.Revision); e != nil {
		return nil, e
	}
	rows := make([]ApplyRow, len(findings))
	for i, f := range findings {
		rows[i] = ApplyRow{f, discoveryInput(source, policy, f), missing[i]}
	}
	var results []ApplyResult
	if s.hooks.ApplyBatch != nil {
		var e error
		results, e = s.hooks.ApplyBatch(ctx, actor, publicSource(source), policy, rows)
		if e != nil {
			return nil, e
		}
	} else {
		if s.hooks.Apply == nil {
			return nil, ErrDenied
		}
		for _, r := range rows {
			id, state, e := s.hooks.Apply(ctx, actor, publicSource(source), policy, r.Finding, r.Input, r.Missing)
			results = append(results, ApplyResult{id, state, e})
		}
	}
	if len(results) != len(rows) {
		return nil, ErrConflict
	}
	out := copyJSON(findings)
	for i, result := range results {
		if result.Err != nil {
			out[i].SyncState = "conflict"
			out[i].SyncError = "scan_sync_conflict"
		} else {
			out[i].AssetID = result.AssetID
			out[i].SyncState = result.State
			out[i].SyncError = ""
		}
	}
	return out, nil
}
func (s *Service) saveFindingBatch(run Run, rows []Finding) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return e
	}
	source, e := sourceFrom(s.store.data, run.SourceID)
	if e != nil || source.Input.Revision != run.SourceRevision {
		return ErrConflict
	}
	next := copyJSON(s.store.data)
	for _, f := range rows {
		old, ok := next.Findings[f.ID]
		if !ok || old.Revision != f.Revision {
			return ErrConflict
		}
		f.Revision++
		next.Findings[f.ID] = f
	}
	return s.store.saveLocked(next)
}
func (s *Service) CancelPolicy(id, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.active {
		if r.Run.PolicyID == id {
			r.reason = code
			r.cancel()
		}
	}
}

// trackImport prevents tenant shutdown from returning with an import still
// holding authority. Cancellation also interrupts lock acquisition in API hooks.
func (s *Service) trackImport(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.started {
		return nil, nil, ErrClosed
	}
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.owner, cancel)
	s.wg.Add(1)
	return owned, func() { stop(); cancel(); s.wg.Done() }, nil
}
