package databasequery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTest(t *testing.T, exec Executor) *Service {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "queries.json"), make([]byte, 32), nil, exec)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s
}
func testSession(t *testing.T, s *Service) SessionResponse {
	t.Helper()
	v, e := s.CreateSession(Session{UserID: "owner", Operator: "Owner", AssetID: "db", AssetName: "QA", Account: "ops", Database: "qa", Binding: "binding"})
	require.NoError(t, e)
	return v
}
func testInput(id string) Input {
	return Input{Input: postgresclient.Input{SQL: "SELECT 'private-literal', $1::text /* private-comment */", Parameters: []json.RawMessage{json.RawMessage(`"private-parameter"`)}, RowLimit: 10, TimeoutSeconds: 5, ReadOnly: true}, RequestID: id}
}
func waitJob(t *testing.T, s *Service, id string) Response {
	t.Helper()
	var r Response
	require.Eventually(t, func() bool { r, _ = s.Get(id, "owner", false); return terminal(r.State) }, 3*time.Second, 5*time.Millisecond)
	return r
}
func TestOwnerIdempotencyEncryptedAuditAndEphemeralResults(t *testing.T) {
	var calls atomic.Int32
	s := openTest(t, func(_ context.Context, _ string, in postgresclient.Input, check func() error) (postgresclient.Result, error) {
		calls.Add(1)
		require.NoError(t, check())
		value := "private-result"
		extra := "private-extra-result"
		return postgresclient.Result{Columns: []sqlclient.Column{{Name: "private-column-alias", DatabaseType: "private-column-type"}}, Rows: [][]*string{{&value}}, ResultSets: []sqlclient.ResultSet{{Columns: []sqlclient.Column{{Name: "extra"}}, Rows: [][]*string{{&extra}}}}, Transaction: "rolled_back"}, nil
	})
	session := testSession(t, s)
	j, e := s.Submit(session.Session, testInput("request-one"), accesspolicies.Origin{Method: "database"}, false, "")
	require.NoError(t, e)
	r := waitJob(t, s, j.ID)
	require.Equal(t, "completed", r.State)
	require.NotNil(t, r.Result)
	assert.Equal(t, "private-result", *r.Result.Rows[0][0])
	assert.Nil(t, r.Summary.Columns)
	assert.Nil(t, r.Summary.Rows)
	assert.Nil(t, r.Summary.ResultSets)
	*r.Result.ResultSets[0].Rows[0][0] = "external-mutation"
	copy, e := s.Get(j.ID, "owner", false)
	require.NoError(t, e)
	assert.Equal(t, "private-extra-result", *copy.Result.ResultSets[0].Rows[0][0])
	assert.NotContains(t, r.SQL, "private-")
	again, e := s.Submit(session.Session, testInput("request-one"), accesspolicies.Origin{}, false, "")
	require.NoError(t, e)
	assert.Equal(t, j.ID, again.ID)
	assert.EqualValues(t, 1, calls.Load())
	changed := testInput("request-one")
	changed.SQL = "SELECT 2"
	_, e = s.Submit(session.Session, changed, accesspolicies.Origin{}, false, "")
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Get(j.ID, "outsider", false)
	assert.ErrorIs(t, e, ErrNotFound)
	foreign, e := s.Get(j.ID, "auditor", true)
	require.NoError(t, e)
	assert.Nil(t, foreign.Result)
	assert.False(t, foreign.ResultAvailable)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "private-")
	var enc envelope
	require.NoError(t, json.Unmarshal(raw, &enc))
	plain, e := s.aead.Open(nil, enc.Nonce, enc.Ciphertext, []byte("jms233/database-queries/v1"))
	require.NoError(t, e)
	for _, v := range []string{"private-literal", "private-comment", "private-parameter", "private-result", "private-extra-result", "private-column-alias", "private-column-type"} {
		assert.NotContains(t, string(plain), v)
	}
	reopened, e := Open(s.path, make([]byte, 32), nil, s.exec)
	require.NoError(t, e)
	defer reopened.Close()
	restored, e := reopened.Get(j.ID, "owner", false)
	require.NoError(t, e)
	assert.Nil(t, restored.Result)
	assert.False(t, restored.ResultAvailable)
	_, e = reopened.Session(session.Token, "owner", "db")
	assert.ErrorIs(t, e, ErrNotFound)
}
func TestReviewDenialCancellationExpiryAndAccessChange(t *testing.T) {
	var calls atomic.Int32
	var allowed atomic.Bool
	allowed.Store(true)
	s := openTest(t, func(ctx context.Context, _ string, _ postgresclient.Input, check func() error) (postgresclient.Result, error) {
		calls.Add(1)
		if e := check(); e != nil {
			return postgresclient.Result{ErrorCode: "access_revoked"}, e
		}
		<-ctx.Done()
		return postgresclient.Result{ErrorCode: "cancelled", Transaction: "rolled_back"}, ctx.Err()
	})
	s.SetGuard(func(j Job) error {
		assert.Contains(t, j.ExecutionSQL, "private-literal")
		if !allowed.Load() {
			return ErrDenied
		}
		return nil
	})
	session := testSession(t, s)
	j, e := s.Submit(session.Session, testInput("review-denied"), accesspolicies.Origin{}, true, "review SQL")
	require.NoError(t, e)
	assert.Zero(t, calls.Load())
	require.NoError(t, s.Resolve(j.ID, "reviewer", false))
	assert.Equal(t, "denied", waitJob(t, s, j.ID).State)
	j, e = s.Submit(session.Session, testInput("review-cancel"), accesspolicies.Origin{}, true, "")
	require.NoError(t, e)
	assert.ErrorIs(t, s.Cancel(j.ID, "outsider", false), ErrNotFound)
	require.NoError(t, s.Cancel(j.ID, "owner", false))
	assert.Equal(t, "cancelled", waitJob(t, s, j.ID).State)
	j, e = s.Submit(session.Session, testInput("review-expire"), accesspolicies.Origin{}, true, "")
	require.NoError(t, e)
	s.expire(j.ID)
	assert.Equal(t, "expired", waitJob(t, s, j.ID).State)
	j, e = s.Submit(session.Session, testInput("review-run"), accesspolicies.Origin{}, true, "review SQL")
	require.NoError(t, e)
	require.NoError(t, s.Resolve(j.ID, "reviewer", true))
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, 5*time.Millisecond)
	allowed.Store(false)
	assert.Equal(t, "cancelled", waitJob(t, s, j.ID).State)
}
func TestSessionClosureCancelsWorkAndReadonlyPolicyIsEnforced(t *testing.T) {
	started := make(chan struct{})
	s := openTest(t, func(ctx context.Context, _ string, in postgresclient.Input, _ func() error) (postgresclient.Result, error) {
		assert.True(t, in.ReadOnly)
		close(started)
		<-ctx.Done()
		return postgresclient.Result{}, ctx.Err()
	})
	session := testSession(t, s)
	s.mu.Lock()
	live := s.sessions[session.ID]
	live.ReadOnly = true
	s.sessions[session.ID] = live
	s.mu.Unlock()
	session.Session = live
	in := testInput("session-cancel")
	in.ReadOnly = false
	j, e := s.Submit(session.Session, in, accesspolicies.Origin{}, false, "")
	require.NoError(t, e)
	<-started
	require.NoError(t, s.DeleteSession(session.Token, "owner"))
	assert.Equal(t, "cancelled", waitJob(t, s, j.ID).State)
	_, e = s.Submit(session.Session, testInput("after-closed"), accesspolicies.Origin{}, false, "")
	assert.ErrorIs(t, e, ErrDenied)
}
func TestPendingRecoveryNeverReplaysSQLAndDropsPayload(t *testing.T) {
	var calls atomic.Int32
	exec := func(context.Context, string, postgresclient.Input, func() error) (postgresclient.Result, error) {
		calls.Add(1)
		return postgresclient.Result{}, nil
	}
	s := openTest(t, exec)
	session := testSession(t, s)
	j, e := s.Submit(session.Session, testInput("pending-recovery"), accesspolicies.Origin{}, true, "review")
	require.NoError(t, e)
	s.Abandon()
	reopened, e := Open(s.path, make([]byte, 32), nil, exec)
	require.NoError(t, e)
	defer reopened.Close()
	r := waitJob(t, reopened, j.ID)
	assert.Equal(t, "interrupted", r.State)
	assert.Equal(t, "unknown", r.Summary.Transaction)
	assert.Nil(t, reopened.jobs[j.ID].Payload)
	assert.Zero(t, calls.Load())
}
func TestPersistenceFailurePreventsExecutionAndResultCacheIsBounded(t *testing.T) {
	var calls atomic.Int32
	s := openTest(t, func(context.Context, string, postgresclient.Input, func() error) (postgresclient.Result, error) {
		calls.Add(1)
		return postgresclient.Result{}, nil
	})
	session := testSession(t, s)
	s.path = filepath.Join(t.TempDir(), "parent", "queries.json")
	require.NoError(t, os.WriteFile(filepath.Dir(s.path), []byte("blocks directory"), 0600))
	_, e := s.Submit(session.Session, testInput("audit-failure"), accesspolicies.Origin{}, false, "")
	require.Error(t, e)
	assert.Zero(t, calls.Load())
	s.mu.Lock()
	for i := range 20 {
		id := strings.Repeat("a", i+1)
		finished := time.Now().Add(time.Duration(i) * time.Second)
		s.jobs[id] = storedJob{Job: Job{ID: id, CreatedAt: finished, FinishedAt: &finished, ResultAvailable: true}}
		s.results[id] = postgresclient.Result{}
	}
	s.pruneResultsLocked()
	assert.Len(t, s.results, 16)
	s.mu.Unlock()
}
func TestSharedPostgresDocumentRecoveryDoesNotReplayUncertainWrite(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for shared PostgreSQL query recovery")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, "database-query-ha-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("database-queries")
	var calls atomic.Int32
	exec := func(context.Context, string, postgresclient.Input, func() error) (postgresclient.Result, error) {
		calls.Add(1)
		return postgresclient.Result{}, errors.New("must not replay")
	}
	s, e := Open(filepath.Join(t.TempDir(), "a.json"), make([]byte, 32), docs, exec)
	require.NoError(t, e)
	session := testSession(t, s)
	j, e := s.Submit(session.Session, testInput("ha-pending-review"), accesspolicies.Origin{}, true, "review")
	require.NoError(t, e)
	s.Abandon()
	next, e := Open(filepath.Join(t.TempDir(), "b.json"), make([]byte, 32), docs, exec)
	require.NoError(t, e)
	defer next.Close()
	assert.Equal(t, "interrupted", waitJob(t, next, j.ID).State)
	assert.Zero(t, calls.Load())
	_, e = next.Session(session.Token, "owner", "db")
	assert.ErrorIs(t, e, ErrNotFound)
}

func TestFailedReviewCancellationPreservesExpiryTimer(t *testing.T) {
	s := openTest(t, func(context.Context, string, postgresclient.Input, func() error) (postgresclient.Result, error) {
		return postgresclient.Result{}, nil
	})
	session := testSession(t, s)
	j, e := s.Submit(session.Session, testInput("cancel-persist-failure"), accesspolicies.Origin{}, true, "review")
	require.NoError(t, e)
	original := s.path
	s.path = filepath.Join(t.TempDir(), "blocked", "queries.json")
	require.NoError(t, os.WriteFile(filepath.Dir(s.path), []byte("blocked"), 0600))
	require.Error(t, s.Cancel(j.ID, "owner", false))
	s.mu.Lock()
	assert.NotNil(t, s.reviewTimers[j.ID])
	assert.Equal(t, "awaiting_review", s.jobs[j.ID].State)
	s.path = original
	s.mu.Unlock()
	s.expire(j.ID)
	assert.Equal(t, "expired", waitJob(t, s, j.ID).State)
}

func TestMySQLSessionControlsDialectAndResultsAreDeepCopied(t *testing.T) {
	value := "private-result"
	known := true
	s := openTest(t, func(_ context.Context, _ string, in postgresclient.Input, _ func() error) (postgresclient.Result, error) {
		assert.Equal(t, "mysql", in.Dialect)
		return postgresclient.Result{Columns: []sqlclient.Column{{Name: "private-column-alias", DatabaseType: "private-column-type"}}, Rows: [][]*string{{&value}}, AffectedRowsKnown: &known, Transaction: "committed"}, nil
	})
	session, e := s.CreateSession(Session{UserID: "owner", Operator: "Owner", AssetID: "mysql", AssetName: "MySQL QA", Account: "qadb", Database: "qa", Binding: "binding", Protocol: "mysql"})
	require.NoError(t, e)
	input := testInput("mysql-dialect")
	input.SQL = "SELECT `private-identifier`, ? # private-comment"
	input.Dialect = "postgresql"
	j, e := s.Submit(session.Session, input, accesspolicies.Origin{}, false, "")
	require.NoError(t, e)
	assert.Equal(t, "mysql", j.Protocol)
	assert.NotContains(t, j.SQL, "private-")
	r := waitJob(t, s, j.ID)
	require.NotNil(t, r.Result)
	*r.Result.Rows[0][0] = "mutated"
	*r.Result.AffectedRowsKnown = false
	again, e := s.Get(j.ID, "owner", false)
	require.NoError(t, e)
	assert.Equal(t, "private-result", *again.Result.Rows[0][0])
	assert.True(t, *again.Result.AffectedRowsKnown)
}

func TestStoppedDatabaseRuntimeCannotMutatePendingWork(t *testing.T) {
	for _, mode := range []string{"abandoned", "owner_cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := openTest(t, func(context.Context, string, postgresclient.Input, func() error) (postgresclient.Result, error) {
				calls.Add(1)
				return postgresclient.Result{}, nil
			})
			session := testSession(t, s)
			job, err := s.Submit(session.Session, testInput("stopped-runtime"), accesspolicies.Origin{}, true, "review")
			require.NoError(t, err)
			before, err := os.ReadFile(s.path)
			require.NoError(t, err)
			if mode == "abandoned" {
				s.Abandon()
			} else {
				owner, cancel := context.WithCancel(context.Background())
				s.BindOwner(owner)
				cancel()
				require.Eventually(t, func() bool { return s.ctx.Err() != nil }, time.Second, time.Millisecond)
			}
			assert.ErrorIs(t, s.Resolve(job.ID, "reviewer", true), ErrBusy)
			assert.ErrorIs(t, s.Cancel(job.ID, "owner", false), ErrBusy)
			assert.ErrorIs(t, s.DeleteSession(session.Token, "owner"), ErrBusy)
			_, err = s.Submit(session.Session, testInput("after-stop"), accesspolicies.Origin{}, false, "")
			assert.ErrorIs(t, err, ErrBusy)
			_, err = s.CreateSession(session.Session)
			assert.ErrorIs(t, err, ErrBusy)
			_, err = s.Session(session.Token, "owner", "db")
			assert.ErrorIs(t, err, ErrNotFound)
			s.expire(job.ID)
			after, err := os.ReadFile(s.path)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			current, err := s.Get(job.ID, "owner", false)
			require.NoError(t, err)
			assert.Equal(t, "awaiting_review", current.State)
			assert.Zero(t, calls.Load())
			s.Abandon()
			next, err := Open(s.path, make([]byte, 32), nil, s.exec)
			require.NoError(t, err)
			defer next.Close()
			assert.Equal(t, "interrupted", waitJob(t, next, job.ID).State)
			assert.Zero(t, calls.Load())
		})
	}
}
