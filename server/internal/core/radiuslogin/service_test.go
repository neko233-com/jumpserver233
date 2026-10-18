package radiuslogin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/radiusclient"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClient func(context.Context, radiusclient.Config, radiusclient.Secrets, radiusclient.Request) (radiusclient.Reply, error)

func (f fakeClient) Exchange(c context.Context, v radiusclient.Config, s radiusclient.Secrets, r radiusclient.Request) (radiusclient.Reply, error) {
	return f(c, v, s, r)
}
func testInput() Input {
	return Input{Config: Config{Enabled: true, ProvisionNew: true, Realm: "test", FactorPolicy: "all", Primary: radiusclient.Config{Host: "radius.synthetic.invalid", Transport: "udp", AllowUDP: true}, Factor: radiusclient.Config{Host: "factor.synthetic.invalid", Transport: "udp", AllowUDP: true}, Bindings: map[string]string{}}, PrimarySecrets: EndpointSecrets{SharedSecret: "synthetic-primary-secret-233"}, FactorSecrets: EndpointSecrets{SharedSecret: "synthetic-factor-secret-233"}}
}
func openTest(t *testing.T, client radiusclient.Client) (*Service, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "radius.json")
	s, e := Open(p, make([]byte, 32), nil, client)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	_, e = s.Save(testInput(), "admin", "admin")
	require.NoError(t, e)
	return s, p
}
func accept(context.Context, radiusclient.Config, radiusclient.Secrets, radiusclient.Request) (radiusclient.Reply, error) {
	return radiusclient.Reply{Code: radiusclient.AccessAccept}, nil
}
func TestEncryptedConfigBindingsPolicyAndRevisions(t *testing.T) {
	s, p := openTest(t, fakeClient(accept))
	raw, e := os.ReadFile(p)
	require.NoError(t, e)
	for _, secret := range []string{"synthetic-primary-secret-233", "radius.synthetic.invalid", "synthetic-factor-secret-233"} {
		assert.NotContains(t, string(raw), secret)
	}
	snap := s.Snapshot()
	assert.True(t, snap.HasPrimarySecret)
	encoded, _ := json.Marshal(snap)
	assert.NotContains(t, string(encoded), "synthetic-primary-secret-233")
	assert.Equal(t, 1, snap.Revision)
	assert.True(t, s.Required("local", false))
	name, e := s.RemoteFor("local", "alice", "")
	require.NoError(t, e)
	assert.Equal(t, "alice", name)
	_, e = s.RemoteFor("ldap", "alice", "ldap")
	assert.ErrorIs(t, e, ErrBinding)
	require.NoError(t, s.BindVerifiedUser("radius-user", "alice", snap.Revision))
	assert.Equal(t, snap.Revision, s.Snapshot().Revision)
	name, e = s.RemoteFor("radius-user", "ignored", "radius")
	require.NoError(t, e)
	assert.Equal(t, "alice", name)
	assert.ErrorIs(t, s.BindVerifiedUser("radius-user", "bob", snap.Revision), ErrConflict)
	pending, e := s.NewPending("radius-user", 1, "192.0.2.1")
	require.NoError(t, e)
	_, e = s.Pending(pending, false, "192.0.2.2")
	require.Error(t, e)
	_, e = s.Pending(pending, false, "192.0.2.1")
	require.NoError(t, e)
	assert.False(t, s.Consume(pending, 1, "192.0.2.2"))
	assert.True(t, s.Consume(pending, 1, "192.0.2.1"))
	assert.False(t, s.Consume(pending, 1, "192.0.2.1"))
	reloaded, e := Open(p, make([]byte, 32), nil, fakeClient(accept))
	require.NoError(t, e)
	defer reloaded.Close()
	assert.Equal(t, s.Snapshot(), reloaded.Snapshot())
	_, e = Open(p, []byte(strings.Repeat("x", 32)), nil, nil)
	assert.Error(t, e)
	_, e = s.Save(testInput(), "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	cfg := s.Snapshot().Config
	cfg.FactorPolicy = "admins"
	_, e = s.Save(Input{Config: cfg}, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.Required("normal", false))
	assert.True(t, s.Required("delegated", true))
	rows, total, e := s.Audit(0, 25)
	require.NoError(t, e)
	assert.Equal(t, 2, total)
	assert.Len(t, rows, 2)
	assert.Equal(t, "admin", rows[0].ActorID)
}
func TestPrimaryChallengeSourceExpiryAndNoSecrets(t *testing.T) {
	var calls atomic.Int32
	s, p := openTest(t, fakeClient(func(_ context.Context, _ radiusclient.Config, _ radiusclient.Secrets, r radiusclient.Request) (radiusclient.Reply, error) {
		calls.Add(1)
		if len(r.State) == 0 {
			return radiusclient.Reply{Code: radiusclient.AccessChallenge, State: []byte("synthetic-state")}, nil
		}
		if r.Password == "code" && string(r.State) == "synthetic-state" {
			return radiusclient.Reply{Code: radiusclient.AccessAccept}, nil
		}
		return radiusclient.Reply{Code: radiusclient.AccessReject}, nil
	}))
	out, e := s.StartPrimary(t.Context(), "alice", "synthetic-password-not-persisted", "192.0.2.1")
	require.NoError(t, e)
	assert.True(t, out.Challenge)
	_, e = s.AnswerPrimary(t.Context(), out.Ticket, "192.0.2.2", "code")
	assert.ErrorIs(t, e, ErrFlow)
	assert.EqualValues(t, 1, calls.Load())
	accepted, e := s.AnswerPrimary(t.Context(), out.Ticket, "192.0.2.1", "code")
	require.NoError(t, e)
	assert.False(t, accepted.Challenge)
	assert.Equal(t, "alice", accepted.Identity.Subject)
	assert.Equal(t, "radius:test", accepted.Identity.Issuer)
	_, e = s.AnswerPrimary(t.Context(), out.Ticket, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrFlow)
	raw, e := os.ReadFile(p)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), out.Ticket)
	assert.NotContains(t, string(raw), "synthetic-password-not-persisted")
	for _, f := range s.data.Flows {
		assert.Empty(t, f.Proof)
		assert.Empty(t, f.RemoteState)
	}
	out, e = s.StartPrimary(t.Context(), "alice", "start", "192.0.2.1")
	require.NoError(t, e)
	s.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	_, e = s.AnswerPrimary(t.Context(), out.Ticket, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrFlow)
}
func factor(t *testing.T, s *Service) (string, FlowStatus) {
	t.Helper()
	token, status, e := s.BeginFactor(FactorInput{UserID: "operator", Username: "alice", RemoteName: "alice", SourceIP: "192.0.2.1", AuthSource: "passkey", Proof: "opaque-encrypted-proof", Browser: true})
	require.NoError(t, e)
	return token, status
}
func TestFactorDurableConsumptionAndRestart(t *testing.T) {
	s, p := openTest(t, fakeClient(accept))
	token, _ := factor(t, s)
	got, status, e := s.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	require.NoError(t, e)
	assert.Equal(t, "consumed", status.State)
	assert.Equal(t, "opaque-encrypted-proof", got.Proof)
	assert.Equal(t, "passkey", got.AuthSource)
	assert.True(t, got.Browser)
	assert.True(t, s.ValidStamp(got.Stamp))
	require.NoError(t, s.BindVerifiedUser("radius-user", "remote", 1))
	assert.True(t, s.ValidStamp(got.Stamp))
	assert.Empty(t, s.data.Flows[flowHash(token)].Proof)
	reload, e := Open(p, make([]byte, 32), nil, fakeClient(accept))
	require.NoError(t, e)
	defer reload.Close()
	_, _, e = reload.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrFlow)
	cfg := s.Snapshot().Config
	_, e = s.Save(Input{Config: cfg}, "admin", "admin")
	require.NoError(t, e)
	assert.False(t, s.ValidStamp(got.Stamp))
}
func TestFactorConcurrentAndAmbiguousRestartNeverReplays(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s, p := openTest(t, fakeClient(func(context.Context, radiusclient.Config, radiusclient.Secrets, radiusclient.Request) (radiusclient.Reply, error) {
		calls.Add(1)
		close(entered)
		<-release
		return radiusclient.Reply{Code: radiusclient.AccessAccept}, nil
	}))
	token, _ := factor(t, s)
	done := make(chan error, 1)
	go func() { _, _, e := s.VerifyFactor(context.Background(), token, "192.0.2.1", "code"); done <- e }()
	<-entered
	_, _, e := s.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrBusy)
	s.Close()
	reload, e := Open(p, make([]byte, 32), nil, fakeClient(accept))
	require.NoError(t, e)
	defer reload.Close()
	status, e := reload.Status(token, "192.0.2.1", "factor")
	require.NoError(t, e)
	assert.Equal(t, "interrupted", status.State)
	_, _, e = reload.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrFlow)
	close(release)
	assert.Error(t, <-done)
	assert.EqualValues(t, 1, calls.Load())
	assert.Empty(t, reload.data.Flows[flowHash(token)].Proof)
}
func TestFactorFailurePersistenceCancellationAndBounds(t *testing.T) {
	s, p := openTest(t, fakeClient(accept))
	token, _ := factor(t, s)
	s.path = t.TempDir()
	_, _, e := s.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	require.Error(t, e)
	s.path = p
	require.NoError(t, s.Cancel(token, "192.0.2.1", "factor"))
	_, _, e = s.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	assert.ErrorIs(t, e, ErrFlow)
	for i := 0; i < 5; i++ {
		factor(t, s)
	}
	_, _, e = s.BeginFactor(FactorInput{UserID: "operator", RemoteName: "alice", SourceIP: "192.0.2.1", Proof: "proof"})
	assert.ErrorIs(t, e, ErrCapacity)
	cfg := s.Snapshot().Config
	cfg.Bindings["operator"] = "mapped"
	cfg.Revision--
	_, e = s.Save(Input{Config: cfg}, "admin", "admin")
	assert.ErrorIs(t, e, ErrConflict)
	assert.Empty(t, s.Snapshot().Bindings)
}
func TestRADIUSPostgresTakeover(t *testing.T) {
	url := os.Getenv("JMS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for PostgreSQL persistence")
	}
	docs, e := storage.OpenPostgres(t.Context(), url, "radius-"+time.Now().Format("150405.000000000"))
	require.NoError(t, e)
	defer docs.Close()
	defer docs.Delete("radius-auth")
	path := filepath.Join(t.TempDir(), "radius.json")
	s, e := Open(path, make([]byte, 32), docs, fakeClient(accept))
	require.NoError(t, e)
	defer s.Close()
	_, e = s.Save(testInput(), "admin", "admin")
	require.NoError(t, e)
	token, _ := factor(t, s)
	s.Close()
	reload, e := Open(path, make([]byte, 32), docs, fakeClient(accept))
	require.NoError(t, e)
	defer reload.Close()
	got, _, e := reload.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	require.NoError(t, e)
	assert.Equal(t, "opaque-encrypted-proof", got.Proof)
	raw, e := docs.Load("radius-auth")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "opaque-encrypted-proof")
}
func TestFactorEmptyResponseChallengePreservesProof(t *testing.T) {
	s, _ := openTest(t, fakeClient(func(_ context.Context, _ radiusclient.Config, _ radiusclient.Secrets, in radiusclient.Request) (radiusclient.Reply, error) {
		if len(in.State) == 0 {
			assert.Empty(t, in.Password)
			return radiusclient.Reply{Code: radiusclient.AccessChallenge, State: []byte("next-round")}, nil
		}
		assert.Equal(t, []byte("next-round"), in.State)
		assert.Equal(t, "code", in.Password)
		return radiusclient.Reply{Code: radiusclient.AccessAccept}, nil
	}))
	token, _ := factor(t, s)
	verified, status, e := s.VerifyFactor(t.Context(), token, "192.0.2.1", "")
	require.NoError(t, e)
	assert.Empty(t, verified.Proof)
	assert.Equal(t, 1, status.Round)
	assert.Equal(t, "pending", status.State)
	verified, status, e = s.VerifyFactor(t.Context(), token, "192.0.2.1", "code")
	require.NoError(t, e)
	assert.Equal(t, "opaque-encrypted-proof", verified.Proof)
	assert.Equal(t, "consumed", status.State)
}
func TestFlowValidationRequiresExactState(t *testing.T) {
	f := flow{Kind: "primary", State: "pending", Username: "alice", RemoteName: "alice", SourceIP: "192.0.2.1", Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, validateFlow(f))
	for _, state := range []string{"pending|verifying", "", "pending|", "other"} {
		f.State = state
		assert.ErrorIs(t, validateFlow(f), ErrInvalid)
	}
}
