package enterpriselogin

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/enterpriseoauth"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const source = "idp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeProvider struct {
	mu      sync.Mutex
	calls   int
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeProvider) Begin(c enterpriseoauth.Config, state, verifier string) (string, error) {
	return enterpriseoauth.NewClient().Begin(c, state, verifier)
}
func (f *fakeProvider) Exchange(ctx context.Context, c enterpriseoauth.Config, secret, code, verifier string) (enterpriseoauth.Identity, error) {
	f.mu.Lock()
	f.calls++
	block, entered := f.block, f.entered
	f.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return enterpriseoauth.Identity{}, ctx.Err()
		}
	}
	return enterpriseoauth.Identity{Subject: "stable-enterprise-subject"}, nil
}
func (f *fakeProvider) Check(context.Context, enterpriseoauth.Config, string) error { return nil }
func input(kind string) Input {
	tenant := "synthetic-tenant"
	client := "synthetic-app"
	agent := ""
	if kind == "wecom" {
		tenant = client
		agent = "10001"
	}
	return Input{Config: Config{Config: enterpriseoauth.Normalize(enterpriseoauth.Config{Provider: kind, ClientID: client, TenantID: tenant, AgentID: agent, CallbackURL: "http://127.0.0.1:5177" + identityscope.Prefix(source) + "/api/v1/authentication/" + kind + "/callback", AllowLoopbackHTTP: true}), Enabled: true}, ClientSecret: "synthetic-enterprise-secret", RequestID: "native-settings-001"}
}
func open(t *testing.T, kind string, f *fakeProvider) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), kind+".json")
	s, e := Open(kind, path, make([]byte, 32), nil, "http://127.0.0.1:5177", identityscope.Prefix(source), f)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	return s, path
}
func TestEnterpriseLoginEncryptedIdempotentSettingsNamespacesAndReopen(t *testing.T) {
	for _, kind := range []string{"wecom", "dingtalk", "feishu"} {
		t.Run(kind, func(t *testing.T) {
			f := &fakeProvider{}
			s, path := open(t, kind, f)
			in := input(kind)
			out, e := s.Save(in, "actor", "admin")
			require.NoError(t, e)
			again, e := s.Save(in, "actor", "admin")
			require.NoError(t, e)
			assert.Equal(t, out, again)
			assert.Len(t, s.Audit(), 1)
			changed := in
			changed.ClientID = "different"
			_, e = s.Save(changed, "actor", "admin")
			assert.ErrorIs(t, e, ErrConflict)
			raw, e := os.ReadFile(path)
			require.NoError(t, e)
			assert.NotContains(t, string(raw), in.ClientSecret)
			assert.NotContains(t, string(raw), in.ClientID)
			namespace := s.Namespace()
			in.Config = out.Config
			in.ClientSecret = "rotated-synthetic-secret"
			in.RequestID = "native-settings-002"
			_, e = s.Save(in, "actor", "admin")
			require.NoError(t, e)
			assert.Equal(t, namespace, s.Namespace())
			s.Close()
			reopened, e := Open(kind, path, make([]byte, 32), nil, "http://127.0.0.1:5177", identityscope.Prefix(source), f)
			require.NoError(t, e)
			defer reopened.Close()
			assert.True(t, reopened.Snapshot().HasClientSecret)
			assert.True(t, reopened.IssuerAllowed(namespace))
			out.Scopes = append(out.Scopes, "mutated")
			assert.Empty(t, reopened.Snapshot().Scopes)
		})
	}
}
func TestEnterpriseLoginFlowProofReplayExpiryPendingAndRevisionChange(t *testing.T) {
	f := &fakeProvider{}
	s, _ := open(t, "feishu", f)
	out, e := s.Save(input("feishu"), "actor", "admin")
	require.NoError(t, e)
	start, e := s.Begin()
	require.NoError(t, e)
	u, e := url.Parse(start.URL)
	require.NoError(t, e)
	_, e = s.Finish(t.Context(), u.Query().Get("state"), "wrong-proof", "synthetic-code")
	assert.ErrorIs(t, e, ErrFlow)
	_, e = s.Finish(t.Context(), u.Query().Get("state"), start.Proof, "synthetic-code")
	assert.ErrorIs(t, e, ErrFlow)
	fresh, e := s.Begin()
	require.NoError(t, e)
	u, _ = url.Parse(fresh.URL)
	identity, e := s.Finish(t.Context(), u.Query().Get("state"), fresh.Proof, "synthetic-code")
	require.NoError(t, e)
	assert.Equal(t, "stable-enterprise-subject", identity.Subject)
	ticket, e := s.NewPending("user-1", identity.Revision, 7)
	require.NoError(t, e)
	p, e := s.Pending(ticket, false)
	require.NoError(t, e)
	assert.Equal(t, 7, p.AuthGeneration)
	assert.True(t, s.Consume(ticket, identity.Revision))
	assert.False(t, s.Consume(ticket, identity.Revision))
	start, e = s.Begin()
	require.NoError(t, e)
	u, _ = url.Parse(start.URL)
	s.Cancel(u.Query().Get("state"), start.Proof)
	_, e = s.Finish(t.Context(), u.Query().Get("state"), start.Proof, "synthetic-code")
	assert.ErrorIs(t, e, ErrFlow)
	next := input("feishu")
	next.Config = out.Config
	next.RequestID = "native-settings-change"
	_, e = s.Save(next, "actor", "admin")
	require.NoError(t, e)
	_, e = s.NewPending("user-1", identity.Revision, 7)
	assert.ErrorIs(t, e, ErrConflict)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	expired, e := s.Begin()
	require.NoError(t, e)
	u, e = url.Parse(expired.URL)
	require.NoError(t, e)
	clock = clock.Add(10 * time.Minute)
	_, e = s.Finish(t.Context(), u.Query().Get("state"), expired.Proof, "synthetic-code")
	assert.ErrorIs(t, e, ErrFlow)
}
func TestEnterpriseLoginCloseCancelsExchangesAndAdmissionIsExplicit(t *testing.T) {
	f := &fakeProvider{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	s, _ := open(t, "dingtalk", f)
	_, e := s.Save(input("dingtalk"), "actor", "admin")
	require.NoError(t, e)
	start, e := s.Begin()
	require.NoError(t, e)
	u, _ := url.Parse(start.URL)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, e := s.Finish(ctx, u.Query().Get("state"), start.Proof, "synthetic-code")
		done <- e
	}()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider exchange did not start")
	}
	s.Close()
	select {
	case e := <-done:
		require.Error(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("provider exchange did not stop")
	}
	assert.False(t, s.Available())
	s.Close()
	another, _ := open(t, "wecom", &fakeProvider{})
	gate := workgate.New()
	gate.SetClosed(true)
	_, e = another.Finish(workgate.WithGate(t.Context(), gate), strings.Repeat("a", 43), strings.Repeat("b", 43), "code")
	assert.ErrorIs(t, e, workgate.ErrDraining)
}

func TestEnterpriseLoginInFlightRevisionAndSnapshotOwnership(t *testing.T) {
	f := &fakeProvider{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	s, _ := open(t, "feishu", f)
	in := input("feishu")
	in.Scopes = []string{"contact:user.base:readonly"}
	out, e := s.Save(in, "actor", "admin")
	require.NoError(t, e)
	out.Scopes[0] = "mutated"
	receipt, e := s.Save(in, "actor", "admin")
	require.NoError(t, e)
	assert.Equal(t, in.Scopes, receipt.Scopes)
	receipt.Scopes[0] = "changed-again"
	assert.Equal(t, in.Scopes, s.Snapshot().Scopes)
	start, e := s.Begin()
	require.NoError(t, e)
	u, e := url.Parse(start.URL)
	require.NoError(t, e)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { _, e := s.Finish(ctx, u.Query().Get("state"), start.Proof, "synthetic-code"); done <- e }()
	select {
	case <-f.entered:
	case <-ctx.Done():
		t.Fatal("provider exchange did not start")
	}
	in.Config = s.Snapshot().Config
	in.ClientSecret = "rotated-during-exchange"
	in.RequestID = "native-settings-inflight"
	_, e = s.Save(in, "actor", "admin")
	require.NoError(t, e)
	close(f.block)
	select {
	case e := <-done:
		assert.ErrorIs(t, e, ErrConflict)
	case <-ctx.Done():
		t.Fatal("provider exchange did not complete")
	}
}
