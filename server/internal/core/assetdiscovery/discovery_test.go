package assetdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fixtureKey = []byte("0123456789abcdef0123456789abcdef")

const fixturePin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func actor() Actor { return Actor{"discovery-operator", "Operator"} }
func sourceInput() SourceInput {
	return SourceInput{RequestID: "source-request-001", Name: "LAN source", Enabled: true, Targets: []string{"192.0.2.1"}, Ports: []int{22}, Template: assets.Input{Protocol: "ssh", Username: "operator"}, Credential: &Credential{Password: "synthetic-discovery-only-password"}}
}
func sourceEdit(s Source) SourceInput {
	var template assets.Input
	_ = json.Unmarshal(s.Template, &template)
	return SourceInput{Provider: s.Provider, Revision: s.Revision, Name: s.Name, Description: s.Description, Enabled: s.Enabled, Targets: s.Targets, Exclude: s.Exclude, Ports: s.Ports, TimeoutMS: s.TimeoutMS, Concurrency: s.Concurrency, GatewayID: s.GatewayID, Template: template}
}
func fixture(t *testing.T, h Hooks) (*Store, *Service, Source, *assets.Service) {
	t.Helper()
	dir := t.TempDir()
	st, e := Open(filepath.Join(dir, "discovery.json"), fixtureKey, nil)
	require.NoError(t, e)
	inventory, e := assets.OpenStore(filepath.Join(dir, "assets.json"), fixtureKey)
	require.NoError(t, e)
	a := assets.NewService(inventory, nil)
	if h.Authorize == nil {
		h.Authorize = func(context.Context, Actor, Source, string) error { return nil }
	}
	if h.Probe == nil {
		h.Probe = func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result {
			return inventoryprobe.Result{Open: true, SSHVerified: true, HostKeyFingerprint: fixturePin}
		}
	}
	if h.ApplyBatch == nil {
		h.ApplyBatch = func(ctx context.Context, _ Actor, source Source, p Policy, rows []ApplyRow) ([]ApplyResult, error) {
			rr := make([]assets.DiscoverySyncRow, len(rows))
			for i, r := range rows {
				rr[i] = assets.DiscoverySyncRow{FindingID: r.Finding.ID, Input: r.Input, Update: p.UpdateExisting, Missing: r.Missing, Options: assets.DiscoverySyncOptions{PolicyID: p.ID, Overwrite: p.OverwriteManualChanges}}
			}
			native, e := a.SyncDiscoveryBatch(ctx, source.ID, rr, time.Now())
			out := []ApplyResult{}
			for _, r := range native {
				out = append(out, ApplyResult{r.Asset.ID, r.State, r.Err})
			}
			return out, e
		}
	}
	h.Bound = a.DiscoveryBound
	s := NewService(st, h)
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(s.Close)
	source, e := st.SaveSource("", sourceInput(), actor(), time.Now())
	require.NoError(t, e)
	return st, s, source, a
}
func policyFor(t *testing.T, st *Store, source Source, auto bool) Policy {
	t.Helper()
	p, e := st.SavePolicy("", PolicyInput{RequestID: "policy-request-001", SourceID: source.ID, SourceRevision: source.Revision, Name: "LAN sync", Enabled: true, AutoImport: auto, TrustNewSSHKeys: auto, UpdateExisting: true, MissingAction: "disable", MissingThreshold: 2}, actor(), time.Now())
	require.NoError(t, e)
	return p
}
func waitRun(t *testing.T, s *Service, r Run) Run {
	t.Helper()
	var final Run
	require.Eventually(t, func() bool { v, e := s.Run(r.ID); final = v; return e == nil && !slicesActive(v.State) }, 4*time.Second, 5*time.Millisecond)
	return final
}
func slicesActive(s string) bool { return s == "scanning" || s == "syncing" || s == "waiting_review" }
func runScan(t *testing.T, s *Service, src Source, p *Policy, request string) Run {
	t.Helper()
	in := RunInput{SourceID: src.ID, SourceRevision: src.Revision, RequestID: request}
	if p != nil {
		in.PolicyID = p.ID
		in.PolicyRevision = p.Revision
	}
	r, e := s.StartRun(context.Background(), in, actor())
	require.NoError(t, e)
	return waitRun(t, s, r)
}
func TestAddressBoundsIPv6ExclusionsAndNoDNS(t *testing.T) {
	rows, e := Addresses([]string{"192.0.2.0/30", "192.0.2.1", "2001:db8::1-2001:db8::2"}, []string{"192.0.2.2", "2001:db8::2/128"})
	require.NoError(t, e)
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::1"}, rows)
	rows, e = Addresses([]string{"192.0.2.0/31"}, nil)
	require.NoError(t, e)
	assert.Len(t, rows, 2)
	rows, e = Addresses([]string{"192.0.2.1", "192.0.2.2"}, []string{"1.0.0.0-192.0.2.1"})
	require.NoError(t, e)
	assert.Equal(t, []string{"192.0.2.2"}, rows)
	for _, v := range []string{"localhost", "0.0.0.0", "224.0.0.1", "fe80::1%eth0", "192.0.2.3-192.0.2.1", "::ffff:192.0.2.1/128"} {
		_, e = Addresses([]string{v}, nil)
		assert.Error(t, e, v)
	}
	for _, v := range []string{"10.0.0.0/8", "2001:db8::/64", "192.0.0.1-192.0.255.255"} {
		_, e = Addresses([]string{v}, nil)
		assert.ErrorIs(t, e, ErrCapacity)
	}
	_, e = normalizePorts([]int{0})
	assert.Error(t, e)
	_, e = normalizePorts([]int{65536})
	assert.Error(t, e)
}
func TestEncryptedSourceCASAndPolicyRevisionConfirmation(t *testing.T) {
	st, _, src, _ := fixture(t, Hooks{})
	p := policyFor(t, st, src, false)
	public, e := json.Marshal(src)
	require.NoError(t, e)
	assert.NotContains(t, string(public), "synthetic-discovery-only-password")
	raw, e := os.ReadFile(st.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "192.0.2.1")
	assert.NotContains(t, string(raw), "synthetic-discovery-only-password")
	retry, e := st.SaveSource("", sourceInput(), actor(), time.Now())
	require.NoError(t, e)
	assert.Equal(t, src, retry)
	edit := sourceEdit(src)
	edit.Description = "updated"
	updated, e := st.SaveSource(src.ID, edit, actor(), time.Now())
	require.NoError(t, e)
	assert.Equal(t, 2, updated.Revision)
	paused, e := st.Policy(p.ID)
	require.NoError(t, e)
	assert.False(t, paused.Enabled)
	assert.Equal(t, 1, paused.SourceRevision)
	edit.Description = "stale"
	_, e = st.SaveSource(src.ID, edit, actor(), time.Now())
	assert.ErrorIs(t, e, ErrConflict)
	retry, e = st.SaveSource(src.ID, sourceEdit(updated), actor(), time.Now())
	require.NoError(t, e)
	assert.Equal(t, updated, retry)
	reopened, e := Open(st.path, fixtureKey, nil)
	require.NoError(t, e)
	r, e := reopened.Source(src.ID)
	require.NoError(t, e)
	assert.Equal(t, updated, r)
	audit, _, e := st.Audit(0, 100)
	require.NoError(t, e)
	rdata, _ := json.Marshal(audit)
	assert.NotContains(t, string(rdata), "synthetic-discovery-only-password")
	assert.Contains(t, string(rdata), "before")
	input := sourceEdit(updated)
	input.Credential = &Credential{}
	cleared, e := st.SaveSource(src.ID, input, actor(), time.Now())
	require.NoError(t, e)
	assert.False(t, cleared.CredentialConfigured)
	require.NoError(t, st.DeleteSource(src.ID, cleared.Revision, actor(), time.Now()))
	require.NoError(t, st.DeleteSource(src.ID, cleared.Revision, actor(), time.Now()))
	_, e = st.Source(src.ID)
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestOneUseImportExactRetryRestartAndCredentialsRemainPrivate(t *testing.T) {
	st, s, src, a := fixture(t, Hooks{})
	p := policyFor(t, st, src, false)
	r := runScan(t, s, src, nil, "manual-scan-001")
	assert.Equal(t, "completed", r.State)
	findings, _, e := st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	require.Len(t, findings, 1)
	f := findings[0]
	in := PreviewInput{SourceID: src.ID, SourceRevision: src.Revision, PolicyID: p.ID, PolicyRevision: p.Revision, Findings: []Selection{{ID: f.ID, Revision: f.Revision}}}
	_, e = s.Preview(context.Background(), in, actor())
	assert.ErrorIs(t, e, ErrPreview)
	in.Findings[0].HostKeyFingerprint = fixturePin
	preview, e := s.Preview(context.Background(), in, actor())
	require.NoError(t, e)
	commit := ImportInput{Token: preview.Token, RequestID: "manual-import-001"}
	result, e := s.Import(context.Background(), commit, actor())
	require.NoError(t, e)
	assert.Equal(t, 1, result.Imported)
	require.Len(t, a.List(), 1)
	retry, e := s.Import(context.Background(), commit, actor())
	require.NoError(t, e)
	assert.Equal(t, result, retry)
	commit.RequestID = "manual-import-002"
	_, e = s.Import(context.Background(), commit, actor())
	assert.ErrorIs(t, e, ErrPreview)
	reopened, e := Open(st.path, fixtureKey, nil)
	require.NoError(t, e)
	resumed := NewService(reopened, s.hooks)
	require.NoError(t, resumed.Start(context.Background()))
	defer resumed.Close()
	commit.RequestID = "manual-import-001"
	retry, e = resumed.Import(context.Background(), commit, actor())
	require.NoError(t, e)
	assert.Equal(t, result, retry)
	assert.Len(t, a.List(), 1)
	raw, _ := json.Marshal(result)
	assert.NotContains(t, string(raw), "synthetic-discovery-only-password")
	assert.NotContains(t, string(raw), "credential")
}
func TestAutomaticSyncMissingRecoveryAndManualDrift(t *testing.T) {
	var online atomic.Bool
	online.Store(true)
	st, s, src, a := fixture(t, Hooks{Probe: func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result {
		if !online.Load() {
			return inventoryprobe.Result{ErrorCode: "scan_unreachable"}
		}
		return inventoryprobe.Result{Open: true, SSHVerified: true, HostKeyFingerprint: fixturePin}
	}})
	p := policyFor(t, st, src, true)
	r := runScan(t, s, src, &p, "auto-import-001")
	assert.Equal(t, 1, r.Imported)
	require.Len(t, a.List(), 1)
	id := a.List()[0].ID
	duplicate, e := s.StartRun(context.Background(), RunInput{SourceID: src.ID, SourceRevision: src.Revision, PolicyID: p.ID, PolicyRevision: p.Revision, RequestID: "auto-import-001"}, actor())
	require.NoError(t, e)
	assert.Equal(t, r, duplicate)
	assert.Len(t, a.List(), 1)
	online.Store(false)
	runScan(t, s, src, &p, "auto-missing-001")
	v, e := a.Get(id)
	require.NoError(t, e)
	assert.False(t, v.AccountDisabled)
	runScan(t, s, src, &p, "auto-missing-002")
	v, e = a.Get(id)
	require.ErrorIs(t, e, assets.ErrAccountDisabled)
	assert.True(t, a.List()[0].AccountDisabled)
	online.Store(true)
	runScan(t, s, src, &p, "auto-return-001")
	v, e = a.Get(id)
	require.NoError(t, e)
	assert.False(t, v.AccountDisabled)
	raw := sourceEdit(src).Template
	raw.Name = "manual-name"
	raw.Host = v.Host
	raw.Port = v.Port
	raw.Username = v.Username
	raw.HostKeyFingerprint = v.HostKeyFingerprint
	raw.Group = v.Group
	_, e = a.Update(id, raw)
	require.NoError(t, e)
	r = runScan(t, s, src, &p, "auto-conflict-001")
	assert.Equal(t, 1, r.Conflicts)
	v, _ = a.Get(id)
	assert.Equal(t, "manual-name", v.Name)
	p.OverwriteManualChanges = true
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), time.Now())
	require.NoError(t, e)
	r = runScan(t, s, src, &p, "auto-overwrite-001")
	assert.Equal(t, 1, r.Updated)
}
func TestCancellationRevocationAndInterruptedRestart(t *testing.T) {
	var denied atomic.Bool
	entered := make(chan struct{}, 1)
	st, s, src, _ := fixture(t, Hooks{Authorize: func(context.Context, Actor, Source, string) error {
		if denied.Load() {
			return ErrDenied
		}
		return nil
	}, Probe: func(ctx context.Context, _ string, _ int, _ string, _ time.Duration, _ inventoryprobe.DialFunc) inventoryprobe.Result {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return inventoryprobe.Result{}
	}})
	in := RunInput{SourceID: src.ID, SourceRevision: src.Revision, RequestID: "cancel-scan-001"}
	r, e := s.StartRun(context.Background(), in, actor())
	require.NoError(t, e)
	<-entered
	_, e = s.Cancel(context.Background(), r.ID, actor())
	require.NoError(t, e)
	final := waitRun(t, s, r)
	assert.Equal(t, "cancelled", final.State)
	denied.Store(true)
	in.RequestID = "denied-scan-001"
	_, e = s.StartRun(context.Background(), in, actor())
	assert.ErrorIs(t, e, ErrDenied)
	denied.Store(false)
	in.RequestID = "stop-scan-001"
	r, e = s.StartRun(context.Background(), in, actor())
	require.NoError(t, e)
	<-entered
	s.Close()
	final, e = s.Run(r.ID)
	require.NoError(t, e)
	assert.Equal(t, "interrupted", final.State)
	st.mu.Lock()
	next := copyJSON(st.data)
	record := next.Runs[r.ID]
	record.State = "waiting_review"
	next.Runs[r.ID] = record
	require.NoError(t, st.saveLocked(next))
	st.mu.Unlock()
	reopened, e := Open(st.path, fixtureKey, nil)
	require.NoError(t, e)
	nextService := NewService(reopened, s.hooks)
	require.NoError(t, nextService.Start(context.Background()))
	defer nextService.Close()
	final, e = nextService.Run(r.ID)
	require.NoError(t, e)
	assert.Equal(t, "interrupted", final.State)
}
func TestScheduledOnceAdvancesWithoutDuplicateAndStorageFailureDoesNotPublish(t *testing.T) {
	st, s, src, _ := fixture(t, Hooks{})
	p := policyFor(t, st, src, false)
	p.Schedule = &operations.Schedule{Kind: "once", RunAt: time.Now().Add(time.Minute)}
	p, e := st.SavePolicy(p.ID, p.PolicyInput, actor(), time.Now())
	require.NoError(t, e)
	s.Tick(p.NextRunAt)
	runs, _, e := s.Runs(src.ID, 0, 100)
	require.NoError(t, e)
	require.Len(t, runs, 1)
	waitRun(t, s, runs[0])
	s.Tick(p.NextRunAt)
	runs, _, _ = s.Runs(src.ID, 0, 100)
	assert.Len(t, runs, 1)
	p, e = st.Policy(p.ID)
	require.NoError(t, e)
	assert.True(t, p.NextRunAt.IsZero())
	st.mu.Lock()
	st.saveHook = func([]byte) error { return errors.New("synthetic storage failure") }
	st.mu.Unlock()
	input := sourceEdit(src)
	input.Description = "not persisted"
	_, e = st.SaveSource(src.ID, input, actor(), time.Now())
	require.Error(t, e)
	current, e := st.Source(src.ID)
	require.NoError(t, e)
	assert.Empty(t, current.Description)
}
func TestDiscoveryImportUsesOneAssetWriteAndBoundedDiscoveryWrites(t *testing.T) {
	st, s, src, a := fixture(t, Hooks{})
	input := sourceEdit(src)
	input.Targets = []string{"192.0.2.1-192.0.2.100"}
	var e error
	src, e = st.SaveSource(src.ID, input, actor(), time.Now())
	require.NoError(t, e)
	p := policyFor(t, st, src, true)
	writes := atomic.Int32{}
	st.mu.Lock()
	st.saveHook = func([]byte) error { writes.Add(1); return nil }
	st.mu.Unlock()
	r := runScan(t, s, src, &p, "bulk-auto-001")
	assert.Equal(t, 100, r.Imported)
	assert.Len(t, a.List(), 100)
	assert.LessOrEqual(t, writes.Load(), int32(5))
	raw, e := os.ReadFile(st.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-discovery-only-password")
}
func TestCatalogRejectsUnsupportedProvidersInvalidCredentialsAndQuotas(t *testing.T) {
	st, _, src, _ := fixture(t, Hooks{})
	for i, change := range []func(*SourceInput){func(v *SourceInput) { v.Provider = "unimplemented-cloud" }, func(v *SourceInput) { v.Targets = []string{"dns.invalid"} }, func(v *SourceInput) { v.Template.Password = "inline-secret" }, func(v *SourceInput) { v.Concurrency = 33 }, func(v *SourceInput) { v.TimeoutMS = 99 }, func(v *SourceInput) { v.GatewayID = "../escape" }, func(v *SourceInput) { v.Template.RDP = nil; v.Template.Protocol = "unknown" }} {
		in := sourceInput()
		in.RequestID = fmt.Sprintf("invalid-request-%d", i)
		change(&in)
		_, e := st.SaveSource("", in, actor(), time.Now())
		assert.Error(t, e)
	}
	_, e := st.SavePolicy("", PolicyInput{SourceID: src.ID, SourceRevision: 1, RequestID: "invalid-policy-001", Name: "bad", OverwriteManualChanges: true}, actor(), time.Now())
	assert.Error(t, e)
	in := sourceEdit(src)
	in.Credential = &Credential{}
	src, e = st.SaveSource(src.ID, in, actor(), time.Now())
	require.NoError(t, e)
	assert.False(t, src.CredentialConfigured)
	raw, e := os.ReadFile(st.path)
	require.NoError(t, e)
	raw[len(raw)/2] ^= 1
	require.NoError(t, os.WriteFile(st.path, raw, 0600))
	_, e = Open(st.path, fixtureKey, nil)
	assert.Error(t, e)
	assert.True(t, strings.HasPrefix(src.ID, "source-"))
}

func TestGatewayOutageNeverCountsHostsAsMissing(t *testing.T) {
	var outage atomic.Bool
	st, s, src, _ := fixture(t, Hooks{Probe: func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result {
		if outage.Load() {
			return inventoryprobe.Result{ErrorCode: "scan_gateway_unavailable"}
		}
		return inventoryprobe.Result{Open: true, SSHVerified: true, HostKeyFingerprint: fixturePin}
	}})
	p := policyFor(t, st, src, true)
	runScan(t, s, src, &p, "gateway-online-001")
	before, _, e := st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	outage.Store(true)
	r := runScan(t, s, src, &p, "gateway-outage-001")
	assert.Equal(t, "failed", r.State)
	assert.Equal(t, "scan_gateway_unavailable", r.ErrorCode)
	after, _, e := st.Findings(src.ID, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, before, after)
}
