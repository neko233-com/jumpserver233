package announcements

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noticeInput(request string) Input {
	return Input{Title: Text{English: "Maintenance", Chinese: "维护公告"}, Body: Text{English: "Plain text <img src=x onerror=alert(1)>", Chinese: "纯文本维护通知"}, RequestID: request}
}
func noticeStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "announcements.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	t.Cleanup(s.Close)
	return s, &now
}

func TestAnnouncementDraftWindowRevisionAndIdempotentReadings(t *testing.T) {
	s, now := noticeStore(t)
	in := noticeInput("create-notice-001")
	n, e := s.Save("", "admin", in)
	require.NoError(t, e)
	rows, total, _, e := s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, rows)
	assert.Zero(t, total)
	in = n.Input
	in.RequestID = "publish-notice-001"
	in.Published = true
	in.StartsAt = now.Add(time.Minute)
	in.EndsAt = now.Add(2 * time.Minute)
	n, e = s.Save(n.ID, "admin", in)
	require.NoError(t, e)
	_, total, _, e = s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	*now = n.StartsAt
	rows, total, unread, e := s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.Equal(t, 1, total)
	assert.Equal(t, 1, unread)
	_, e = s.Acknowledge(n.ID, "reader", n.Revision-1)
	assert.ErrorIs(t, e, ErrConflict)
	r, e := s.Acknowledge(n.ID, "reader", n.Revision)
	require.NoError(t, e)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	*now = now.Add(time.Second)
	again, e := s.Acknowledge(n.ID, "reader", n.Revision)
	require.NoError(t, e)
	assert.Equal(t, r, again)
	after, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Equal(t, raw, after)
	rows, _, unread, e = s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	assert.True(t, rows[0].Read)
	assert.Zero(t, unread)
	_, _, otherUnread, e := s.Page("other-reader", false, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, otherUnread)
	in = n.Input
	in.RequestID = "change-notice-001"
	in.Body.English = "Revised maintenance"
	updated, e := s.Save(n.ID, "admin", in)
	require.NoError(t, e)
	rows, _, unread, e = s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	assert.False(t, rows[0].Read)
	assert.Equal(t, 1, unread)
	_, e = s.Acknowledge(n.ID, "reader", n.Revision)
	assert.ErrorIs(t, e, ErrConflict)
	*now = updated.EndsAt
	_, total, _, e = s.Page("reader", false, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	_, e = s.Acknowledge(n.ID, "reader", updated.Revision)
	assert.ErrorIs(t, e, ErrNotFound)
	_, total, _, e = s.Page("admin", true, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, total)
}

func TestAnnouncementRequestReplayEncryptionRestartAndDelete(t *testing.T) {
	s, _ := noticeStore(t)
	in := noticeInput("durable-create-001")
	in.Published = true
	n, e := s.Save("", "admin", in)
	require.NoError(t, e)
	for i := 0; i < 2; i++ {
		replay, e := s.Save("", "admin", in)
		require.NoError(t, e)
		assert.Equal(t, n, replay)
	}
	changed := in
	changed.Body.English = "different"
	_, e = s.Save("", "admin", changed)
	assert.ErrorIs(t, e, ErrConflict)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), in.Title.English)
	assert.NotContains(t, string(raw), in.Body.Chinese)
	_, e = Open(s.path, bytes.Repeat([]byte{1}, 32), nil)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = s.Acknowledge(n.ID, "reader", n.Revision)
	require.NoError(t, e)
	s.Close()
	peer, e := Open(s.path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	rows, _, unread, e := peer.Page("reader", false, 0, 20)
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.True(t, rows[0].Read)
	assert.Zero(t, unread)
	require.NoError(t, peer.Delete(n.ID, "admin", n.Revision, "durable-delete-001"))
	require.NoError(t, peer.Delete(n.ID, "admin", n.Revision, "durable-delete-001"))
	assert.ErrorIs(t, peer.Delete(n.ID, "admin", n.Revision+1, "durable-delete-001"), ErrConflict)
	replay, e := peer.Save("", "admin", in)
	require.NoError(t, e)
	assert.Equal(t, n.ID, replay.ID)
	rows, total, _, e := peer.Page("admin", true, 0, 20)
	require.NoError(t, e)
	assert.Empty(t, rows)
	assert.Zero(t, total)
	audit, total, e := peer.Audit(0, 20)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	assert.Equal(t, "delete", audit[0].Action)
	auditRaw, e := json.Marshal(audit)
	require.NoError(t, e)
	assert.NotContains(t, string(auditRaw), in.Body.English)
}

func TestAnnouncementValidationPaginationAndFailedPersistenceIsAtomic(t *testing.T) {
	s, _ := noticeStore(t)
	for _, modify := range []func(*Input){func(in *Input) { in.Title = Text{} }, func(in *Input) { in.Body = Text{} }, func(in *Input) { in.Severity = "unknown" }, func(in *Input) { in.RequestID = "short" }, func(in *Input) { in.Body.English = "bad\x00content" }, func(in *Input) { in.Title.English = strings.Repeat("x", 201) }, func(in *Input) { in.Revision = 1 }, func(in *Input) { in.StartsAt = time.Now(); in.EndsAt = in.StartsAt.Add(-time.Second) }} {
		in := noticeInput("invalid-notice-001")
		modify(&in)
		_, e := s.Save("", "admin", in)
		require.Error(t, e)
	}
	original := s.path
	s.path = filepath.Dir(s.path)
	_, e := s.Save("", "admin", noticeInput("failed-write-001"))
	require.Error(t, e)
	s.path = original
	_, total, _, e := s.Page("admin", true, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, total)
	in := noticeInput("failed-write-001")
	in.Title.Chinese = strings.Repeat("中", 200)
	in.Body.English = "line one\r\nline two"
	first, e := s.Save("", "admin", in)
	require.NoError(t, e)
	assert.Equal(t, "line one\nline two", first.Body.English)
	in = noticeInput("pinned-notice-001")
	in.Pinned = true
	pin, e := s.Save("", "admin", in)
	require.NoError(t, e)
	rows, total, _, e := s.Page("admin", true, 0, 1)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	assert.Equal(t, pin.ID, rows[0].ID)
	rows, _, _, e = s.Page("admin", true, 100, 20)
	require.NoError(t, e)
	assert.Empty(t, rows)
	_, _, _, e = s.Page("admin", true, -1, 20)
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
	after, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Equal(t, future, after)
}

func TestAnnouncementPostgresPlatformScopeAndTakeover(t *testing.T) {
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for announcements PostgreSQL integration")
	}
	docs, e := storage.OpenPostgres(context.Background(), database, fmt.Sprintf("announcements-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	platform, e := docs.Scoped("platform-identity")
	require.NoError(t, e)
	defer platform.Delete("announcements")
	s, e := Open(filepath.Join(t.TempDir(), "announcements.json"), make([]byte, 32), platform)
	require.NoError(t, e)
	in := noticeInput("postgres-notice-001")
	in.Published = true
	n, e := s.Save("", "admin", in)
	require.NoError(t, e)
	r, e := s.Acknowledge(n.ID, "reader", n.Revision)
	require.NoError(t, e)
	s.Close()
	peer, e := Open(filepath.Join(t.TempDir(), "announcements.json"), make([]byte, 32), platform)
	require.NoError(t, e)
	defer peer.Close()
	again, e := peer.Save("", "admin", in)
	require.NoError(t, e)
	assert.Equal(t, n.ID, again.ID)
	againRead, e := peer.Acknowledge(n.ID, "reader", n.Revision)
	require.NoError(t, e)
	assert.Equal(t, r, againRead)
	raw, e := platform.Load("announcements")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), in.Body.English)
	_, e = docs.Load("announcements")
	assert.ErrorIs(t, e, storage.ErrDocumentNotFound)
}
