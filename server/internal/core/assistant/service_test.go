package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/aichat"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keyText = "synthetic-assistant-api-key"

func settingsInput() SettingsInput {
	secret := keyText
	return SettingsInput{Settings: aichat.Settings{Endpoint: "https://provider.example/v1/chat/completions", Model: "synthetic-model", MaxTokens: 512}, Secret: &secret, Enabled: true, RequestID: "assistant-settings-001"}
}
func input() Input {
	return Input{RequestID: "assistant-question-001", Message: "Explain pwd", Locale: "en", Consent: true}
}
func allow(context.Context) error { return nil }
func fixture(t *testing.T) *Service {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "assistant.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	_, e = s.SaveSettings("admin", settingsInput())
	require.NoError(t, e)
	s.complete = func(context.Context, aichat.Settings, string, []aichat.Message) (aichat.Result, error) {
		return aichat.Result{Text: "pwd prints the directory", PromptTokens: 5, CompletionTokens: 4}, nil
	}
	return s
}
func TestAssistantReceiptsRevisionIsolationEncryptionAndArchive(t *testing.T) {
	s := fixture(t)
	var calls atomic.Int32
	s.complete = func(_ context.Context, _ aichat.Settings, secret string, m []aichat.Message) (aichat.Result, error) {
		calls.Add(1)
		assert.Equal(t, keyText, secret)
		assert.NotContains(t, m[len(m)-1].Content, keyText)
		return aichat.Result{Text: "safe reply " + keyText}, nil
	}
	in := input()
	in.Message += " " + keyText
	result, e := s.Submit(t.Context(), "operator", in, allow)
	require.NoError(t, e)
	assert.Equal(t, "completed", result.Turn.Status)
	assert.NotContains(t, result.Turn.Reply, keyText)
	assert.NotContains(t, result.Turn.Message, keyText)
	again, e := s.Submit(t.Context(), "operator", in, allow)
	require.NoError(t, e)
	assert.Equal(t, result, again)
	assert.EqualValues(t, 1, calls.Load())
	changed := in
	changed.Message += " changed"
	_, e = s.Submit(t.Context(), "operator", changed, allow)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Get("other", result.ConversationID, false)
	assert.ErrorIs(t, e, ErrNotFound)
	auditView, e := s.Get("auditor", result.ConversationID, true)
	require.NoError(t, e)
	assert.Len(t, auditView.Turns, 1)
	public, e := s.Settings()
	require.NoError(t, e)
	raw, e := json.Marshal(public)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), keyText)
	assert.NotContains(t, string(raw), "\"secret\"")
	file, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(file), keyText)
	assert.NotContains(t, string(file), "Explain pwd")
	require.NoError(t, s.Archive("operator", result.ConversationID, result.Revision, "archive-request-001"))
	require.NoError(t, s.Archive("operator", result.ConversationID, result.Revision, "archive-request-001"))
	page, e := s.Page("operator", false, false, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, page.Total)
	page, e = s.Page("operator", false, true, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, page.Total)
	s.Close()
	reopened, e := Open(s.path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer reopened.Close()
	again, e = reopened.Submit(t.Context(), "operator", in, allow)
	require.NoError(t, e)
	assert.Equal(t, result.Turn, again.Turn)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	_, e = Open(s.path, wrongKey, nil)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestAssistantConcurrentRequestCallsProviderOnce(t *testing.T) {
	s := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.complete = func(ctx context.Context, _ aichat.Settings, _ string, _ []aichat.Message) (aichat.Result, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return aichat.Result{Text: "one response"}, nil
		case <-ctx.Done():
			return aichat.Result{}, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, e := s.Submit(t.Context(), "operator", input(), allow); done <- e }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.Submit(t.Context(), "operator", input(), allow)
			assert.NoError(t, e)
			assert.Equal(t, "pending", r.Turn.Status)
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, calls.Load())
	close(release)
	require.NoError(t, <-done)
}
func TestAssistantIntentSurvivesResultWriteFailureAndRestartWithoutResending(t *testing.T) {
	s := fixture(t)
	var saves, calls int
	s.saveHook = func([]byte) error {
		saves++
		if saves == 2 {
			return errors.New("synthetic disk failure")
		}
		return nil
	}
	s.complete = func(context.Context, aichat.Settings, string, []aichat.Message) (aichat.Result, error) {
		calls++
		return aichat.Result{Text: "remote answer"}, nil
	}
	_, e := s.Submit(t.Context(), "operator", input(), allow)
	assert.ErrorIs(t, e, ErrBusy)
	assert.Equal(t, 1, calls)
	s.Close()
	beforeOpen, e := os.ReadFile(s.path)
	require.NoError(t, e)
	reopened, e := Open(s.path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer reopened.Close()
	afterOpen, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.Equal(t, beforeOpen, afterOpen, "offline preflight Open must remain read-only")
	reopened.complete = func(context.Context, aichat.Settings, string, []aichat.Message) (aichat.Result, error) {
		t.Error("must not resend an uncertain request")
		return aichat.Result{}, ErrBusy
	}
	r, e := reopened.Submit(t.Context(), "operator", input(), allow)
	require.NoError(t, e)
	assert.Equal(t, "uncertain", r.Turn.Status)
	assert.Empty(t, r.Turn.Reply)
}
func TestAssistantRevocationCloseAndAdmissionDoNotReleaseAnswers(t *testing.T) {
	for _, mode := range []string{"revoke", "settings", "close"} {
		t.Run(mode, func(t *testing.T) {
			s := fixture(t)
			var revoked atomic.Bool
			entered := make(chan struct{})
			s.complete = func(ctx context.Context, _ aichat.Settings, _ string, _ []aichat.Message) (aichat.Result, error) {
				close(entered)
				<-ctx.Done()
				return aichat.Result{Text: "must not release"}, ctx.Err()
			}
			guard := func(context.Context) error {
				if revoked.Load() {
					return ErrDenied
				}
				return nil
			}
			done := make(chan SubmitResult, 1)
			go func() { r, e := s.Submit(t.Context(), "operator", input(), guard); assert.NoError(t, e); done <- r }()
			<-entered
			switch mode {
			case "revoke":
				revoked.Store(true)
			case "settings":
				in := settingsInput()
				in.Revision = 1
				in.RequestID = "assistant-settings-002"
				in.Enabled = false
				_, e := s.SaveSettings("admin", in)
				require.NoError(t, e)
			case "close":
				s.Close()
				s.Close()
			}
			select {
			case r := <-done:
				assert.Empty(t, r.Turn.Reply)
				assert.Contains(t, []string{"revoked", "uncertain"}, r.Turn.Status)
			case <-time.After(2 * time.Second):
				t.Fatal("assistant request did not cancel")
			}
		})
	}
	s := fixture(t)
	gate := workgate.New()
	s.SetAdmissionGate(gate)
	gate.SetClosed(true)
	_, e := s.Submit(t.Context(), "operator", input(), allow)
	assert.ErrorIs(t, e, workgate.ErrDraining)
	assert.Empty(t, s.data.Conversations)
	assert.Empty(t, gate.Snapshot())
}
func TestAssistantSettingsReplayConsentAndForeignRevision(t *testing.T) {
	s := fixture(t)
	before, e := s.Settings()
	require.NoError(t, e)
	replayed, e := s.SaveSettings("admin", settingsInput())
	require.NoError(t, e)
	assert.Equal(t, before, replayed)
	bad := settingsInput()
	bad.Model = "changed"
	_, e = s.SaveSettings("admin", bad)
	assert.ErrorIs(t, e, ErrConflict)
	bad.RequestID = "assistant-settings-002"
	_, e = s.SaveSettings("admin", bad)
	assert.ErrorIs(t, e, ErrConflict)
	question := input()
	question.Consent = false
	_, e = s.Submit(t.Context(), "operator", question, allow)
	assert.ErrorIs(t, e, ErrInvalid)
	result, e := s.Submit(t.Context(), "operator", input(), allow)
	require.NoError(t, e)
	question = input()
	question.RequestID = "assistant-question-002"
	question.ConversationID = result.ConversationID
	question.Revision = result.Revision - 1
	_, e = s.Submit(t.Context(), "operator", question, allow)
	assert.ErrorIs(t, e, ErrConflict)
	question.Revision = result.Revision
	_, e = s.Submit(t.Context(), "other", question, allow)
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestAssistantConversationCapacityAndContextBudget(t *testing.T) {
	s := fixture(t)
	result, e := s.Submit(t.Context(), "operator", input(), allow)
	require.NoError(t, e)
	s.mu.Lock()
	c := s.data.Conversations[result.ConversationID]
	for i := 1; i < 13; i++ {
		turn := c.Turns[0]
		turn.ID = fmt.Sprintf("turn-%032x", i)
		turn.RequestID = fmt.Sprintf("context-request-%03d", i)
		turn.Reply = string(makeReply(32768))
		c.Turns = append(c.Turns, turn)
	}
	c.Revision += 12
	s.data.Conversations[c.ID] = c
	s.mu.Unlock()
	s.complete = func(_ context.Context, _ aichat.Settings, _ string, m []aichat.Message) (aichat.Result, error) {
		size := 0
		for _, v := range m {
			size += len(v.Content)
		}
		assert.LessOrEqual(t, size, 120*1024)
		assert.Equal(t, "system", m[0].Role)
		assert.Equal(t, "user", m[len(m)-1].Role)
		return aichat.Result{Text: "bounded answer"}, nil
	}
	in := input()
	in.RequestID = "context-question-002"
	in.ConversationID = c.ID
	in.Revision = c.Revision
	_, e = s.Submit(t.Context(), "operator", in, allow)
	require.NoError(t, e)
	s.mu.Lock()
	c = s.data.Conversations[c.ID]
	for len(c.Turns) < 32 {
		turn := c.Turns[0]
		turn.ID = fmt.Sprintf("turn-%032x", len(c.Turns)+100)
		turn.RequestID = fmt.Sprintf("capacity-request-%03d", len(c.Turns))
		c.Turns = append(c.Turns, turn)
	}
	s.data.Conversations[c.ID] = c
	s.mu.Unlock()
	s.complete = func(context.Context, aichat.Settings, string, []aichat.Message) (aichat.Result, error) {
		t.Error("capacity rejection must precede provider I/O")
		return aichat.Result{}, ErrBusy
	}
	in.RequestID = "capacity-question-003"
	in.Revision = c.Revision
	_, e = s.Submit(t.Context(), "operator", in, allow)
	assert.ErrorIs(t, e, ErrCapacity)
}
func makeReply(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'x'
	}
	return out
}
func TestAssistantPostgresOrganizationIsolationAndTakeover(t *testing.T) {
	database := os.Getenv("JMS_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("requires JMS_TEST_DATABASE_URL")
	}
	docs, e := storage.OpenPostgres(t.Context(), database, fmt.Sprintf("assistant-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	a, e := docs.Scoped("org-a")
	require.NoError(t, e)
	b, e := docs.Scoped("org-b")
	require.NoError(t, e)
	defer a.Delete("assistant")
	defer b.Delete("assistant")
	path := filepath.Join(t.TempDir(), "assistant.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	_, e = s.SaveSettings("admin", settingsInput())
	require.NoError(t, e)
	s.Close()
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	v, e := peer.Settings()
	require.NoError(t, e)
	assert.True(t, v.Configured)
	other, e := Open(filepath.Join(t.TempDir(), "assistant.json"), make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	v, e = other.Settings()
	require.NoError(t, e)
	assert.False(t, v.Configured)
	raw, e := a.Load("assistant")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), keyText)
}
