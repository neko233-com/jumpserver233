package accesspolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInput() Input {
	return Input{Name: "source control", Kind: Asset, Enabled: true, Priority: 50, Action: "deny", Timezone: "UTC"}
}
func openTest(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "policies.json"), nil)
	require.NoError(t, e)
	return s
}
func saveTest(t *testing.T, s *Store, in Input) Rule {
	t.Helper()
	r, e := s.Save("", in, "admin", nil)
	require.NoError(t, e)
	return r
}
func TestSourcesScopesAndPriority(t *testing.T) {
	s := openTest(t)
	in := testInput()
	in.GroupID = "operators"
	in.NodeID = "parent"
	in.Account = "ops"
	in.Methods = []string{"ssh"}
	in.Sources = []string{"192.0.2.0/24", "2001:db8::1-2001:db8::10"}
	r := saveTest(t, s, in)
	scope := Scope{Kind: Asset, UserID: "user", GroupIDs: []string{"operators"}, AssetID: "host", NodeIDs: []string{"child", "parent"}, Account: "ops", Origin: Origin{SourceIP: "192.0.2.25", Method: "ssh"}}
	for _, source := range []string{"192.0.2.0", "192.0.2.255", "::ffff:192.0.2.20", "2001:db8::1", "2001:db8::10"} {
		scope.SourceIP = source
		d := s.Decide(scope, time.Now())
		assert.False(t, d.Allowed, source)
		assert.Equal(t, r.ID, d.RuleID)
	}
	for _, source := range []string{"192.0.3.25", "2001:db8::11"} {
		scope.SourceIP = source
		assert.True(t, s.Decide(scope, time.Now()).Allowed)
	}
	scope.SourceIP = "unknown"
	assert.Equal(t, "unknown_source", s.Decide(scope, time.Now()).Reason)
	scope.SourceIP = "192.0.2.25"
	scope.GroupIDs = nil
	assert.True(t, s.Decide(scope, time.Now()).Allowed)
	scope.GroupIDs = []string{"operators"}
	scope.NodeIDs = []string{"child"}
	assert.True(t, s.Decide(scope, time.Now()).Allowed)
	scope.NodeIDs = []string{"parent"}
	scope.Method = "exec"
	assert.True(t, s.Decide(scope, time.Now()).Allowed)
	scope.Method = "ssh"
	in.NodeID = ""
	in.GroupID = ""
	in.Priority = 10
	in.Action = "allow"
	allow := saveTest(t, s, in)
	assert.True(t, s.Decide(scope, time.Now()).Allowed)
	in.Action = "deny"
	deny := saveTest(t, s, in)
	assert.Equal(t, deny.ID, s.Decide(scope, time.Now()).RuleID)
	in.Action = "allow"
	in.Priority = 1
	override := saveTest(t, s, in)
	assert.Equal(t, override.ID, s.Decide(scope, time.Now()).RuleID)
	copy := s.List()
	copy[0].Methods[0] = "sftp"
	copy[0].Sources[0] = "*"
	assert.Equal(t, override.ID, s.Decide(scope, time.Now()).RuleID)
	assert.NoError(t, s.Delete(allow.ID, allow.Revision, "admin", nil))
	assert.ErrorIs(t, s.Delete(allow.ID, allow.Revision, "admin", nil), ErrNotFound)
}
func TestWeeklyWindowsTimezoneAndDST(t *testing.T) {
	s := openTest(t)
	in := testInput()
	in.Timezone = "America/New_York"
	in.Windows = []Window{{Days: []int{0}, Start: 60, End: 120}}
	saveTest(t, s, in)
	scope := Scope{Kind: Asset, UserID: "u", Origin: Origin{SourceIP: "127.0.0.1", Method: "ssh"}}
	for _, value := range []string{"2026-11-01T05:00:00Z", "2026-11-01T06:59:59Z"} {
		at, e := time.Parse(time.RFC3339, value)
		require.NoError(t, e)
		assert.False(t, s.Decide(scope, at).Allowed, value)
	}
	for _, value := range []string{"2026-11-01T04:59:59Z", "2026-11-01T07:00:00Z", "2026-11-02T06:30:00Z"} {
		at, e := time.Parse(time.RFC3339, value)
		require.NoError(t, e)
		assert.True(t, s.Decide(scope, at).Allowed, value)
	}
}
func TestValidationAndPersistence(t *testing.T) {
	invalid := []func(*Input){func(in *Input) { in.Kind = "unknown" }, func(in *Input) { in.Action = "review" }, func(in *Input) { in.Timezone = "Local" }, func(in *Input) { in.Timezone = "../UTC" }, func(in *Input) { in.Timezone = "Mars/Olympus" }, func(in *Input) { in.Priority = -1 }, func(in *Input) { in.UserID = "u"; in.GroupID = "g" }, func(in *Input) { in.AssetID = "a"; in.NodeID = "n" }, func(in *Input) { in.Sources = []string{"192.0.2.5-192.0.2.1"} }, func(in *Input) { in.Sources = []string{"fe80::1%eth0"} }, func(in *Input) { in.Sources = []string{"::ffff:192.0.2.0/120"} }, func(in *Input) { in.Sources = []string{"https://example.invalid"} }, func(in *Input) { in.Windows = []Window{{Days: []int{1}, Start: 120, End: 60}} }, func(in *Input) { in.Windows = []Window{{Days: []int{1, 1}, End: 1440}} }, func(in *Input) { in.Windows = []Window{{Days: []int{7}, End: 1440}} }, func(in *Input) { in.Methods = []string{"browser"} }, func(in *Input) { in.Methods = []string{"ssh", "ssh"} }, func(in *Input) { in.Kind = Login; in.AssetID = "a" }, func(in *Input) { in.Kind = Method }, func(in *Input) { in.Name = "bad\nname" }}
	for i, mutate := range invalid {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s := openTest(t)
			in := testInput()
			mutate(&in)
			_, e := s.Save("", in, "admin", nil)
			require.ErrorIs(t, e, ErrInvalid)
			assert.Empty(t, s.List())
		})
	}
	s := openTest(t)
	in := testInput()
	in.Kind = Login
	in.UserID = "operator"
	in.Sources = []string{"*"}
	r := saveTest(t, s, in)
	r.Name = "changed"
	_, e := s.Save(r.ID, r.Input, "admin", nil)
	require.NoError(t, e)
	_, e = s.Save(r.ID, r.Input, "admin", nil)
	require.ErrorIs(t, e, ErrConflict)
	loaded, e := Open(s.path, nil)
	require.NoError(t, e)
	assert.Equal(t, 2, loaded.List()[0].Revision)
	info, e := os.Stat(s.path)
	require.NoError(t, e)
	if os.PathSeparator != '\\' {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	bad := []byte(`{"rules":{"acl-00000000000000000000000000000000":{"id":"acl-00000000000000000000000000000000","name":"bad","kind":"login","action":"deny","timezone":"invalid","revision":1}},"audit":[]}`)
	require.NoError(t, os.WriteFile(s.path, bad, 0600))
	_, e = Open(s.path, nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestLockoutGuardAndFailedWriteRollback(t *testing.T) {
	s := openTest(t)
	scope := Scope{Kind: Login, UserID: "admin", Origin: Origin{SourceIP: "127.0.0.1"}}
	in := testInput()
	in.Kind = Login
	_, e := s.Save("", in, "admin", &scope)
	require.ErrorIs(t, e, ErrLockout)
	assert.Empty(t, s.List())
	in.Action = "allow"
	in.UserID = "admin"
	in.Priority = 0
	allow, e := s.Save("", in, "admin", &scope)
	require.NoError(t, e)
	in.Action = "deny"
	in.UserID = ""
	in.Priority = 50
	_, e = s.Save("", in, "admin", &scope)
	require.NoError(t, e)
	require.ErrorIs(t, s.Delete(allow.ID, allow.Revision, "admin", &scope), ErrLockout)
	assert.Len(t, s.List(), 2)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("file"), 0600))
	s.path = filepath.Join(blocker, "child.json")
	before := s.List()
	in = testInput()
	_, e = s.Save("", in, "admin", nil)
	require.Error(t, e)
	assert.Equal(t, before, s.List())
	_, e = s.Check(Scope{Kind: Login, UserID: "operator", Origin: Origin{SourceIP: "127.0.0.1"}}, time.Now())
	require.Error(t, e)
}
func TestDenialAuditRetentionPaginationAndConcurrency(t *testing.T) {
	s := openTest(t)
	saveTest(t, s, testInput())
	scope := Scope{Kind: Asset, UserID: "u", AssetID: "a", Origin: Origin{SourceIP: "127.0.0.1", Method: "ssh"}}
	at := time.Now().UTC()
	d, e := s.Check(scope, at)
	require.NoError(t, e)
	assert.False(t, d.Allowed)
	_, e = s.Check(scope, at.Add(time.Second))
	require.NoError(t, e)
	assert.Len(t, s.Audit(100), 2)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.Check(scope, at.Add(2*time.Second))
			assert.NoError(t, e)
			_ = s.List()
		}()
	}
	wg.Wait()
	assert.Len(t, s.Audit(100), 2)
	s.mu.Lock()
	s.data.Audit = make([]Audit, MaxAudit)
	for i := range s.data.Audit {
		s.data.Audit[i] = Audit{ID: fmt.Sprint(i), ActorID: "u", At: at, Action: "denied"}
	}
	s.mu.Unlock()
	_, e = s.Check(scope, at.Add(2*time.Minute))
	require.NoError(t, e)
	events, total := s.AuditPage(MaxAudit-2, 25)
	assert.Equal(t, MaxAudit, total)
	assert.Len(t, events, 2)
	assert.Equal(t, "1", events[1].ID)
	loaded, e := Open(s.path, nil)
	require.NoError(t, e)
	assert.Len(t, loaded.Audit(1), 1)
}
func TestPostgresAccessPoliciesReload(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for PostgreSQL access policy persistence")
	}
	docs, e := storage.OpenPostgres(context.Background(), url, fmt.Sprintf("policy-test-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("access-policies")
	s, e := Open(filepath.Join(t.TempDir(), "policies.json"), docs)
	require.NoError(t, e)
	in := testInput()
	in.UserID = "operator"
	in.Sources = []string{"192.0.2.0/24"}
	r := saveTest(t, s, in)
	scope := Scope{Kind: Asset, UserID: "operator", Origin: Origin{SourceIP: "192.0.2.5", Method: "ssh"}}
	_, e = s.Check(scope, time.Now())
	require.NoError(t, e)
	copy, e := Open(filepath.Join(t.TempDir(), "new-node.json"), docs)
	require.NoError(t, e)
	assert.Equal(t, r.ID, copy.Decide(scope, time.Now()).RuleID)
	events, total := copy.AuditPage(0, 10)
	assert.Equal(t, 2, total)
	assert.Equal(t, "denied", events[0].Action)
	raw, e := docs.Load("access-policies")
	require.NoError(t, e)
	assert.True(t, json.Valid(raw))
}
