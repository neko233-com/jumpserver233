package accountrisks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRiskActor() Actor { return Actor{ID: "risk-owner", Name: "Risk owner"} }
func observation() Observation {
	return Observation{Ref: Ref{AssetID: "asset-a", AccountID: "account-a", AssetName: "Synthetic host", Username: "synthetic-risk-operator"}, Identity: strings.Repeat("a", 64), CredentialType: "password", Active: true, CreatedAt: time.Now().UTC().Add(-100 * 24 * time.Hour), RotatedAt: time.Now().UTC().Add(-100 * 24 * time.Hour), SourceVersion: strings.Repeat("b", 64), Binding: strings.Repeat("c", 64), Checks: []Check{{Kind: "weak_password", Severity: "high", Reasons: []string{"short"}}}}
}
func riskService(t *testing.T) (*Service, *Snapshot, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "risks.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	snapshot := &Snapshot{Accounts: []Observation{observation()}, Groups: map[string][]Member{}}
	s.SetRunner(func(ctx context.Context, _ Actor, _ Policy, _ time.Time, commit func(Snapshot) error) error {
		return commit(*snapshot)
	}, func(Actor) (func(), error) { return func() {}, nil })
	return s, snapshot, path
}
func scanRisk(t *testing.T, s *Service, id string) Scan {
	t.Helper()
	r, e := s.Scan(context.Background(), testRiskActor(), id, s.Policy().Revision, false)
	require.NoError(t, e)
	require.Equal(t, "succeeded", r.State)
	return r
}
func TestRiskScanReviewReappearanceAndEncryptedReload(t *testing.T) {
	s, snapshot, path := riskService(t)
	first := scanRisk(t, s, "first-request")
	page, e := s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	f := page.Results[0]
	ignored, e := s.Review(f.ID, f.Revision, "ignore", "Accepted temporary exception", testRiskActor())
	require.NoError(t, e)
	assert.Equal(t, "ignored", ignored.State)
	scanRisk(t, s, "second-request")
	page, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, "ignored", page.Results[0].State)
	snapshot.Accounts[0].Binding = strings.Repeat("d", 64)
	scanRisk(t, s, "changed-credential")
	page, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, "open", page.Results[0].State)
	assert.Equal(t, 2, page.Results[0].Occurrences)
	snapshot.Accounts[0].Checks = nil
	scanRisk(t, s, "resolved-credential")
	page, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, "resolved", page.Results[0].State)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Synthetic host")
	assert.NotContains(t, string(raw), "synthetic-risk-operator")
	assert.NotContains(t, string(raw), "Accepted temporary exception")
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	same, e := peer.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, page, same)
	peer.SetRunner(func(context.Context, Actor, Policy, time.Time, func(Snapshot) error) error {
		t.Fatal("committed request must not rescan")
		return nil
	}, func(Actor) (func(), error) { return func() {}, nil })
	retry, e := peer.Scan(context.Background(), testRiskActor(), first.RequestID, first.PolicyRevision, false)
	require.NoError(t, e)
	assert.Equal(t, first, retry)
	_, e = Open(path, bytes.Repeat([]byte{1}, 32), nil)
	require.Error(t, e)
}
func TestRiskScanAtomicFailureCancellationAndPolicyFence(t *testing.T) {
	s, snapshot, _ := riskService(t)
	scanRisk(t, s, "initial")
	before, e := s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	count := 0
	s.saveHook = func([]byte) error {
		count++
		if count == 2 {
			return errors.New("owned persistence failure")
		}
		return nil
	}
	snapshot.Accounts[0].Checks = nil
	_, e = s.Scan(context.Background(), testRiskActor(), "failed", 1, false)
	require.Error(t, e)
	after, e := s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	s.saveHook = nil
	entered := make(chan struct{})
	s.SetRunner(func(ctx context.Context, _ Actor, _ Policy, _ time.Time, commit func(Snapshot) error) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}, func(Actor) (func(), error) { return func() {}, nil })
	done := make(chan error, 1)
	go func() { _, e := s.Scan(context.Background(), testRiskActor(), "cancelled", 1, false); done <- e }()
	<-entered
	runs, _, e := s.Scans(0, 100)
	require.NoError(t, e)
	require.Equal(t, "running", runs[0].State)
	require.NoError(t, s.Cancel(runs[0].ID))
	require.Error(t, <-done)
	after, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	entered = make(chan struct{})
	go func() { _, e := s.Scan(context.Background(), testRiskActor(), "config-fenced", 1, false); done <- e }()
	<-entered
	p := s.Policy()
	p.MinPasswordLength = 20
	_, e = s.Configure(p, testRiskActor())
	require.NoError(t, e)
	require.Error(t, <-done)
	_, e = s.Review(before.Results[0].ID, before.Results[0].Revision, "ignore", "", testRiskActor())
	assert.ErrorIs(t, e, ErrConflict)
}
func TestRiskGroupsHideUnseenIdentitiesAndDoNotCallAliasesReuse(t *testing.T) {
	s, snapshot, _ := riskService(t)
	a := observation()
	b := a
	b.AccountID = "account-b"
	b.AssetID = "asset-b"
	c := a
	c.AccountID = "account-c"
	c.AssetID = "asset-c"
	c.Identity = strings.Repeat("d", 64)
	group := strings.Repeat("f", 64)
	for _, o := range []*Observation{&a, &b, &c} {
		o.Checks = []Check{{Kind: "duplicate_password", Severity: "high", Reasons: []string{"different_remote_identities"}, GroupID: group}}
	}
	snapshot.Accounts = []Observation{a, b, c}
	snapshot.Groups[group] = []Member{{a.Ref, a.Identity}, {b.Ref, b.Identity}, {c.Ref, c.Identity}}
	scanRisk(t, s, "grouped")
	page, e := s.List(Query{Limit: 50}, func(r Ref) bool { return r.AccountID != "account-c" }, nil)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
	for id, e := range s.data.Findings {
		if e.AccountID == "account-a" {
			_, ok := s.VisibleFind(id, func(r Ref) bool { return r.AccountID != "account-c" }, nil)
			assert.False(t, ok)
		}
	}
	page, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	require.Len(t, page.Results, 3)
	for _, f := range page.Results {
		assert.NotContains(t, fmt.Sprint(f), group)
		if f.AccountID == "account-a" {
			assert.Equal(t, 1, f.PeerCount)
			require.Len(t, f.Peers, 1)
			assert.Equal(t, "account-c", f.Peers[0].AccountID)
		}
	}
}
func TestRiskScheduleRevocationRetentionAndNoPartialCollector(t *testing.T) {
	s, _, _ := riskService(t)
	var allowed atomic.Bool
	allowed.Store(true)
	s.SetRunner(func(context.Context, Actor, Policy, time.Time, func(Snapshot) error) error { return nil }, func(Actor) (func(), error) {
		if !allowed.Load() {
			return nil, ErrDenied
		}
		return func() {}, nil
	})
	_, e := s.Scan(context.Background(), testRiskActor(), "no-complete-snapshot", 1, false)
	require.Error(t, e)
	page, e := s.List(Query{Limit: 1}, nil, nil)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
	p := s.Policy()
	p.Enabled = true
	_, e = s.Configure(p, testRiskActor())
	require.NoError(t, e)
	allowed.Store(false)
	s.tick()
	p = s.Policy()
	assert.False(t, p.Enabled)
	assert.Equal(t, "denied", p.LastError)
	audit, _, e := s.Audit(0, 100)
	require.NoError(t, e)
	assert.Equal(t, "schedule_paused", audit[0].Action)
	assert.Equal(t, "scan_failed", audit[2].Action)
}

func TestRiskRetryStillRequiresAuthorityAndHasBoundedDeadline(t *testing.T) {
	s, _, _ := riskService(t)
	scanRisk(t, s, "existing")
	s.SetRunner(func(ctx context.Context, _ Actor, _ Policy, _ time.Time, commit func(Snapshot) error) error {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		assert.WithinDuration(t, time.Now().Add(time.Minute), deadline, time.Second)
		return commit(Snapshot{})
	}, func(Actor) (func(), error) { return func() {}, nil })
	scanRisk(t, s, "bounded")
	s.SetRunner(nil, func(Actor) (func(), error) { return nil, ErrDenied })
	// Retrying an old receipt must pass the same live authorization check.
	s.collect = func(context.Context, Actor, Policy, time.Time, func(Snapshot) error) error { return nil }
	_, e := s.Scan(context.Background(), testRiskActor(), "existing", 1, false)
	assert.ErrorIs(t, e, ErrDenied)
}

func TestRiskRetentionAndMalformedObservationPreserveSnapshot(t *testing.T) {
	s, snapshot, _ := riskService(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	scanRisk(t, s, "before")
	before, e := s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	snapshot.Accounts[0].Identity = strings.Repeat("z", 64)
	_, e = s.Scan(context.Background(), testRiskActor(), "malformed", 1, false)
	assert.ErrorIs(t, e, ErrInvalid)
	after, e := s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	snapshot.Accounts = nil
	scanRisk(t, s, "resolved")
	now = now.Add(91 * 24 * time.Hour)
	scanRisk(t, s, "pruned")
	after, e = s.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	assert.Empty(t, after.Results)
}

func BenchmarkRiskListTenThousandReusedCredentials(b *testing.B) {
	s := &Service{data: state{Policy: DefaultPolicy(), Findings: map[string]entry{}, Groups: map[string][]Member{}}}
	group := strings.Repeat("f", 64)
	members := []Member{}
	for i := range MaxAccounts {
		o := observation()
		o.AccountID = fmt.Sprintf("account-%d", i)
		if i == MaxAccounts-1 {
			o.Identity = strings.Repeat("d", 64)
		}
		id := fmt.Sprintf("risk-%d", i)
		s.data.Findings[id] = entry{Finding: Finding{Ref: o.Ref, ID: id, Kind: "duplicate_password", State: "open", LastSeen: time.Now(), PolicyRevision: 1}, Identity: o.Identity, GroupID: group}
		members = append(members, Member{o.Ref, o.Identity})
	}
	s.data.Groups[group] = members
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		page, e := s.List(Query{Limit: 50, State: "open"}, nil, nil)
		if e != nil || page.Total != MaxAccounts {
			b.Fatal("risk page unavailable")
		}
	}
}
func TestRiskPostgresTakeoverPreservesFindingsAndInterruptsUnfinishedScans(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("risk-state-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	t.Cleanup(func() { _ = docs.Delete("account-risks"); _ = docs.Close() })
	s, e := Open(filepath.Join(t.TempDir(), "risks.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	o := observation()
	s.SetRunner(func(_ context.Context, _ Actor, _ Policy, _ time.Time, commit func(Snapshot) error) error {
		return commit(Snapshot{Accounts: []Observation{o}, Groups: map[string][]Member{}})
	}, func(Actor) (func(), error) { return func() {}, nil })
	scanRisk(t, s, "pg-complete")
	require.NoError(t, s.mutate(func(d *state) error {
		d.Scans = append(d.Scans, Scan{ID: "risk-scan-owned", RequestID: "interrupted", Actor: testRiskActor(), PolicyRevision: 1, State: "running", StartedAt: time.Now()})
		return nil
	}))
	s.Close()
	peer, e := Open(filepath.Join(t.TempDir(), "unused.json"), make([]byte, 32), docs)
	require.NoError(t, e)
	defer peer.Close()
	page, e := peer.List(Query{Limit: 50}, nil, nil)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	runs, _, e := peer.Scans(0, 10)
	require.NoError(t, e)
	assert.Equal(t, "interrupted", runs[0].State)
	raw, e := docs.Load("account-risks")
	require.NoError(t, e)
	assert.False(t, bytes.Contains(raw, []byte(o.Username)))
}
