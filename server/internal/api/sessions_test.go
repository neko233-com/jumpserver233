package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

type sessionTestTerminal struct{}

func (sessionTestTerminal) Read([]byte) (int, error)       { return 0, io.EOF }
func (sessionTestTerminal) Write(data []byte) (int, error) { return len(data), nil }
func (sessionTestTerminal) Resize(int, int) error          { return nil }
func (sessionTestTerminal) Close() error                   { return nil }

func TestSessionListAndReplayRoutes(t *testing.T) {
	dataDir := t.TempDir()
	broker := gateway.NewBroker(dataDir, []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "test-host", Username: "ops"}, sessionTestTerminal{}, nil
	})
	defer broker.CloseAll()
	router := NewRouter("test", Dependencies{Sessions: broker})

	created, err := broker.Create(context.Background(), gateway.CreateRequest{AssetID: "asset-01", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := broker.Close(created.SessionID); err != nil {
		t.Fatalf("close session: %v", err)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?limit=10&offset=0", nil)
	listRequest.RemoteAddr = "127.0.0.1:12345"
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("GET sessions status = %d, want 200: %s", listResponse.Code, listResponse.Body.String())
	}
	var body struct {
		Results []gateway.SessionRecord `json:"results"`
		Total   int                     `json:"total"`
		Active  int                     `json:"active_total"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&body); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if body.Total != 1 || body.Active != 0 || len(body.Results) != 1 || body.Results[0].SessionID != created.SessionID || !body.Results[0].ReplayAvailable {
		t.Fatalf("session list response = %#v", body)
	}
	commandsResponse := httptest.NewRecorder()
	commandsRequest := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+created.SessionID+"/commands?limit=10&offset=0", nil)
	commandsRequest.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(commandsResponse, commandsRequest)
	if commandsResponse.Code != http.StatusOK || !strings.Contains(commandsResponse.Body.String(), `"total":0`) {
		t.Fatalf("GET session commands status/body = %d %s", commandsResponse.Code, commandsResponse.Body.String())
	}
	if got := commandsResponse.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("commands cache control = %q", got)
	}

	invalidRequest := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?limit=0", nil)
	invalidRequest.RemoteAddr = "127.0.0.1:12345"
	invalidResponse := httptest.NewRecorder()
	router.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("GET sessions invalid pagination status = %d, want 400", invalidResponse.Code)
	}

	replayRequest := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+created.SessionID+"/replay", nil)
	replayRequest.RemoteAddr = "127.0.0.1:12345"
	replayResponse := httptest.NewRecorder()
	router.ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusOK {
		t.Fatalf("GET replay status = %d, want 200: %s", replayResponse.Code, replayResponse.Body.String())
	}
	if got := replayResponse.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("replay cache control = %q", got)
	}
	if !strings.HasPrefix(string(replayResponse.Body.Bytes()), "\x1f\x8b") {
		t.Fatalf("replay response is not gzip data")
	}
	compressed, err := gzip.NewReader(replayResponse.Body)
	if err != nil {
		t.Fatalf("open replay gzip stream: %v", err)
	}
	defer compressed.Close()
	decoded, err := io.ReadAll(compressed)
	if err != nil {
		t.Fatalf("decode replay gzip stream: %v", err)
	}
	if !strings.Contains(string(decoded), `"version":2`) {
		t.Fatalf("replay stream is not asciinema v2 data: %s", decoded)
	}
}

func TestSessionRoutesRequireConfiguredAdminToken(t *testing.T) {
	const token = "test-session-admin-token"
	router := NewRouter("test", Dependencies{
		Sessions:   gateway.NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), nil),
		AdminToken: token,
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	request.RemoteAddr = "192.0.2.10:12345"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("GET sessions without token status = %d, want 401", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET sessions with token status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestDeleteSessionRouteStopsActiveSession(t *testing.T) {
	broker := gateway.NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "test-host", Username: "ops"}, sessionTestTerminal{}, nil
	})
	defer broker.CloseAll()
	created, err := broker.Create(context.Background(), gateway.CreateRequest{AssetID: "asset-01", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+created.SessionID, nil)
	request.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	NewRouter("test", Dependencies{Sessions: broker}).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("DELETE session status = %d, want 204: %s", response.Code, response.Body.String())
	}
	rows, total, activeTotal, err := broker.ListSessions(0, 10)
	if err != nil {
		t.Fatalf("list stopped session: %v", err)
	}
	if total != 1 || activeTotal != 0 || rows[0].Status != "ended" || rows[0].EndReason != "closed_by_client" {
		t.Fatalf("stopped session record = %#v, total %d", rows, total)
	}
}

func TestOperatorsCanOnlyListStopAndReplayTheirOwnSessions(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := identities.CreateUser("operator.alice", "an-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	aliceLogin, err := identities.Authenticate(alice.Username, "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identities.CreateUser("operator.bob", "another-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	broker := gateway.NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: assetID, Username: "deploy"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	create := func(assetID string, operator coreauth.User) gateway.CreatedSession {
		t.Helper()
		session, err := broker.Create(context.Background(), gateway.CreateRequest{AssetID: assetID, Cols: 80, Rows: 24, OperatorID: operator.ID, Operator: operator.Username})
		if err != nil {
			t.Fatalf("create %s session: %v", operator.Username, err)
		}
		return session
	}
	aliceReplay := create("alice-replay", alice)
	if err := broker.Close(aliceReplay.SessionID); err != nil {
		t.Fatal(err)
	}
	bobReplay := create("bob-replay", bob)
	if err := broker.Close(bobReplay.SessionID); err != nil {
		t.Fatal(err)
	}
	aliceActive := create("alice-active", alice)
	bobActive := create("bob-active", bob)
	router := NewRouter("test", Dependencies{Auth: identities, Sessions: broker})
	const remote = "192.0.2.15:43210"

	listed := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions?limit=10&offset=0", "", aliceLogin.AccessToken, remote)
	var page struct {
		Results []gateway.SessionRecord `json:"results"`
		Total   int                     `json:"total"`
		Active  int                     `json:"active_total"`
	}
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &page) != nil || page.Total != 2 || page.Active != 1 || len(page.Results) != 2 {
		t.Fatalf("operator session list = %d %s", listed.Code, listed.Body.String())
	}
	for _, record := range page.Results {
		if record.OperatorID != alice.ID {
			t.Fatalf("operator session response leaked another owner: %#v", record)
		}
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions/"+bobReplay.SessionID+"/replay", "", aliceLogin.AccessToken, remote); response.Code != http.StatusNotFound {
		t.Fatalf("operator replay of foreign session = %d, want 404", response.Code)
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions/"+bobReplay.SessionID+"/commands", "", aliceLogin.AccessToken, remote); response.Code != http.StatusNotFound {
		t.Fatalf("operator command audit of foreign session = %d, want 404", response.Code)
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions/"+aliceReplay.SessionID+"/commands", "", aliceLogin.AccessToken, remote); response.Code != http.StatusOK {
		t.Fatalf("operator command audit of own session = %d %s", response.Code, response.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodDelete, "/api/v1/sessions/"+bobActive.SessionID, "", aliceLogin.AccessToken, remote); response.Code != http.StatusNotFound {
		t.Fatalf("operator stop of foreign session = %d, want 404", response.Code)
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions/"+aliceReplay.SessionID+"/replay", "", aliceLogin.AccessToken, remote); response.Code != http.StatusOK {
		t.Fatalf("operator replay of own session = %d %s", response.Code, response.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodDelete, "/api/v1/sessions/"+aliceActive.SessionID, "", aliceLogin.AccessToken, remote); response.Code != http.StatusNoContent {
		t.Fatalf("operator stop of own session = %d %s", response.Code, response.Body.String())
	}
	adminPage := doJSONRequest(t, router, http.MethodGet, "/api/v1/sessions?limit=10&offset=0", "", admin.AccessToken, remote)
	if adminPage.Code != http.StatusOK || !strings.Contains(adminPage.Body.String(), bobActive.SessionID) {
		t.Fatalf("administrator session list omitted other sessions: %d %s", adminPage.Code, adminPage.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodDelete, "/api/v1/sessions/"+bobActive.SessionID, "", admin.AccessToken, remote); response.Code != http.StatusNoContent {
		t.Fatalf("administrator stop = %d %s", response.Code, response.Body.String())
	}
}
