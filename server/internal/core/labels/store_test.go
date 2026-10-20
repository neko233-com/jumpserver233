package labels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func labelStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "labels.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s
}
func saveLabel(t *testing.T, s *Store, name, value, request string) Label {
	t.Helper()
	l, e := s.Save("", "admin", Input{Name: name, Value: value, RequestID: request})
	require.NoError(t, e)
	return l
}

func TestLabelInheritanceOverridesKeysAndBindingsHaveIndependentRevisions(t *testing.T) {
	s := labelStore(t)
	prod := saveLabel(t, s, "Environment", "production", "create-prod-001")
	stage := saveLabel(t, s, "environment", "staging", "create-stage-001")
	dev := saveLabel(t, s, "Environment", "development", "create-dev-001")
	team := saveLabel(t, s, "Team", "Ops", "create-team-001")
	root, child, host := Resource{"node", "root"}, Resource{"node", "child"}, Resource{"asset", "host"}
	_, e := s.Bind(root, "admin", BindingInput{LabelIDs: []string{prod.ID, team.ID}, RequestID: "root-bind-001"})
	require.NoError(t, e)
	_, e = s.Bind(child, "admin", BindingInput{LabelIDs: []string{stage.ID}, RequestID: "child-bind-001"})
	require.NoError(t, e)
	rows, e := s.Effective([]Resource{host, child, root})
	require.NoError(t, e)
	require.Len(t, rows, 2)
	assert.Equal(t, stage.ID, rows[0].ID)
	assert.True(t, rows[0].Inherited)
	assert.Equal(t, child, rows[0].Source)
	assert.Equal(t, team.ID, rows[1].ID)
	direct, e := s.Bind(host, "admin", BindingInput{LabelIDs: []string{dev.ID}, RequestID: "host-bind-001"})
	require.NoError(t, e)
	assert.Equal(t, 1, direct.Revision)
	snapshot, effective, e := s.View([]Resource{host, child, root})
	require.NoError(t, e)
	assert.Equal(t, direct, snapshot)
	assert.Equal(t, direct.LabelIDs[0], effective[0].ID)
	rows, e = s.Effective([]Resource{host, child, root})
	require.NoError(t, e)
	assert.Equal(t, dev.ID, rows[0].ID)
	assert.False(t, rows[0].Inherited)
	_, e = s.Bind(host, "admin", BindingInput{LabelIDs: []string{prod.ID, dev.ID}, Revision: 1, RequestID: "duplicate-key-001"})
	assert.ErrorIs(t, e, ErrInvalid)
	renamed := team.Input
	renamed.Name = "environment"
	renamed.RequestID = "rename-key-001"
	_, e = s.Save(team.ID, "admin", renamed)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Bind(host, "admin", BindingInput{Revision: 1, RequestID: "clear-host-001"})
	require.NoError(t, e)
	_, e = s.Bind(host, "admin", BindingInput{LabelIDs: []string{dev.ID}, Revision: 0, RequestID: "stale-clear-001"})
	assert.ErrorIs(t, e, ErrConflict)
	rows, e = s.Effective([]Resource{host, child, root})
	require.NoError(t, e)
	assert.Equal(t, stage.ID, rows[0].ID)
	// Moving the host selects a different ancestry without copying stored labels.
	rows, e = s.Effective([]Resource{host, root})
	require.NoError(t, e)
	assert.Equal(t, prod.ID, rows[0].ID)
	rows[0].Name = "mutated"
	again, e := s.Choices()
	require.NoError(t, e)
	assert.NotContains(t, fmt.Sprint(again), "mutated")
}

func TestLabelRequestReplayEncryptionRestartAndDeletionDoNotRestoreBindings(t *testing.T) {
	s := labelStore(t)
	in := Input{Name: "服务", Value: "production", Description: "sensitive catalog note", Color: "#ABCDEF", RequestID: "durable-label-001"}
	l, e := s.Save("", "admin", in)
	require.NoError(t, e)
	assert.Equal(t, "#abcdef", l.Color)
	replay, e := s.Save("", "admin", in)
	require.NoError(t, e)
	assert.Equal(t, l, replay)
	modified := in
	modified.Value = "changed"
	_, e = s.Save("", "admin", modified)
	assert.ErrorIs(t, e, ErrConflict)
	resource := Resource{"asset", "host"}
	bindingInput := BindingInput{LabelIDs: []string{l.ID}, RequestID: "durable-bind-001"}
	b, e := s.Bind(resource, "admin", bindingInput)
	require.NoError(t, e)
	// Return values never alias persisted binding or immutable receipt slices.
	b.LabelIDs[0] = "damaged"
	replayed, e := s.Bind(resource, "admin", bindingInput)
	require.NoError(t, e)
	assert.Equal(t, []string{l.ID}, replayed.LabelIDs)
	current, e := s.Binding(resource)
	require.NoError(t, e)
	assert.Equal(t, []string{l.ID}, current.LabelIDs)
	require.ErrorIs(t, s.Delete(l.ID, "admin", l.Revision, "delete-label-001", nil), ErrInUse)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), in.Description)
	_, e = Open(s.path, bytes.Repeat([]byte{1}, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	s.Close()
	peer, e := Open(s.path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	replayed, e = peer.Bind(resource, "admin", bindingInput)
	require.NoError(t, e)
	assert.Equal(t, current, replayed)
	_, e = peer.Bind(resource, "admin", BindingInput{Revision: current.Revision, RequestID: "clear-binding-001"})
	require.NoError(t, e)
	require.NoError(t, peer.Delete(l.ID, "admin", l.Revision, "delete-label-001", nil))
	after, e := os.ReadFile(s.path)
	require.NoError(t, e)
	require.NoError(t, peer.Delete(l.ID, "admin", l.Revision, "delete-label-001", nil))
	unchanged, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Equal(t, after, unchanged)
	_, e = peer.Save("", "admin", in)
	require.NoError(t, e)
	_, total, e := peer.Page("", 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	_, e = peer.Bind(resource, "admin", bindingInput)
	require.NoError(t, e)
	current, e = peer.Binding(resource)
	require.NoError(t, e)
	assert.Empty(t, current.LabelIDs)
	assert.Equal(t, 2, current.Revision)
	audit, total, e := peer.Audit(0, 20)
	require.NoError(t, e)
	assert.Equal(t, 4, total)
	encoded, e := json.Marshal(audit)
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), in.Description)
	// Deleting a catalog row clears only bindings proven to refer to deleted resources.
	dead := saveLabel(t, peer, "dead", "orphan", "orphan-label-001")
	_, e = peer.Bind(Resource{"asset", "deleted-host"}, "admin", BindingInput{LabelIDs: []string{dead.ID}, RequestID: "orphan-bind-001"})
	require.NoError(t, e)
	require.NoError(t, peer.Delete(dead.ID, "admin", dead.Revision, "orphan-delete-001", func(r Resource) bool { return r.ID != "deleted-host" }))
}

func TestLabelValidationAtomicWriteFailureAndFutureFormatRefusal(t *testing.T) {
	s := labelStore(t)
	for _, in := range []Input{{Name: "", RequestID: "invalid-label-001"}, {Name: "bad\x00key", RequestID: "invalid-label-001"}, {Name: strings.Repeat("中", 65), RequestID: "invalid-label-001"}, {Name: "ok", Color: "red", RequestID: "invalid-label-001"}, {Name: "ok", RequestID: "short"}} {
		_, e := s.Save("", "admin", in)
		require.Error(t, e)
	}
	original := s.path
	s.path = filepath.Dir(original)
	_, e := s.Save("", "admin", Input{Name: "atomic", RequestID: "failed-write-001"})
	require.Error(t, e)
	s.path = original
	_, total, e := s.Page("", 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	l := saveLabel(t, s, "atomic", "", "failed-write-001")
	_, e = s.Save("", "admin", Input{Name: "ATOMIC", RequestID: "duplicate-label-001"})
	assert.ErrorIs(t, e, ErrConflict)
	for _, in := range []BindingInput{{LabelIDs: []string{l.ID, l.ID}, RequestID: "invalid-bind-001"}, {LabelIDs: []string{"label-" + strings.Repeat("a", 32)}, RequestID: "invalid-bind-001"}, {Revision: -1, RequestID: "invalid-bind-001"}} {
		_, e = s.Bind(Resource{"asset", "host"}, "admin", in)
		assert.Error(t, e)
	}
	_, e = s.Bind(Resource{"asset", "../escape"}, "admin", BindingInput{RequestID: "invalid-bind-001"})
	assert.ErrorIs(t, e, ErrInvalid)
	_, _, e = s.Page("", -1, 20)
	assert.ErrorIs(t, e, ErrInvalid)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	box.Version = 2
	future, e := json.Marshal(box)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(s.path, future, 0600))
	_, e = Open(s.path, make([]byte, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	s.Close()
	_, e = s.Choices()
	assert.ErrorIs(t, e, ErrClosed)
}

func TestLabelConcurrentIdempotentRequestsUseOneReceipt(t *testing.T) {
	s := labelStore(t)
	in := Input{Name: "Concurrent", RequestID: "concurrent-label-001"}
	var wg sync.WaitGroup
	results := make(chan Label, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := s.Save("", "admin", in); results <- v; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	id := ""
	for v := range results {
		if id == "" {
			id = v.ID
		}
		assert.Equal(t, id, v.ID)
	}
	assert.Len(t, s.data.Receipts, 1)
	assert.Len(t, s.data.Audit, 1)
}

func TestLabelPostgresOrganizationIsolationAndTakeover(t *testing.T) {
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for labels PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), database, fmt.Sprintf("labels-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("org-a")
	require.NoError(t, e)
	b, e := docs.Scoped("org-b")
	require.NoError(t, e)
	defer a.Delete("labels")
	defer b.Delete("labels")
	path := filepath.Join(t.TempDir(), "labels.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	l := saveLabel(t, s, "Tenant", "private", "postgres-label-001")
	resource := Resource{"asset", "host"}
	in := BindingInput{LabelIDs: []string{l.ID}, RequestID: "postgres-bind-001"}
	saved, e := s.Bind(resource, "admin", in)
	require.NoError(t, e)
	s.Close()
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	again, e := peer.Bind(resource, "admin", in)
	require.NoError(t, e)
	assert.Equal(t, saved, again)
	isolated, e := Open(filepath.Join(t.TempDir(), "labels.json"), make([]byte, 32), b)
	require.NoError(t, e)
	defer isolated.Close()
	_, total, e := isolated.Page("", 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	raw, e := a.Load("labels")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "private")
	_, e = docs.Load("labels")
	assert.ErrorIs(t, e, storage.ErrDocumentNotFound)
}
