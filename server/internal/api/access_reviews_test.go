package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestAssetLoginReviewApprovesOneSessionAndScopesStatusToOperator(t *testing.T) {
	dataDir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dataDir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate(operator.Username, "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	otherOperator, err := identities.CreateUser("operator.two", "another-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := identities.Authenticate(otherOperator.Username, "another-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	assets := testAssetService(t)
	requireReview := true
	asset, err := assets.Create(coreassets.Input{
		Name: "review-host", Host: "192.0.2.20", Username: "deploy", Password: "test-only",
		Port: 22, HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &requireReview,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(dataDir, "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Create(coregrants.Input{UserID: operator.ID, AssetID: asset.ID, Account: "deploy", Actions: []string{"connect"}}, "admin.user"); err != nil {
		t.Fatal(err)
	}
	reviews, err := coreaccessreviews.OpenStore(filepath.Join(dataDir, "access-reviews.json"))
	if err != nil {
		t.Fatal(err)
	}
	sessionsCreated := 0
	broker := gateway.NewBroker(dataDir, []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		sessionsCreated++
		return gateway.AssetInfo{ID: assetID, Name: "review-host", Username: "deploy"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	router := NewRouter("test", Dependencies{Assets: assets, AccessReviews: reviews, Auth: identities, Grants: grants, Sessions: broker})
	createSession := `{"asset_id":"` + asset.ID + `","cols":80,"rows":24}`
	requested := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if requested.Code != http.StatusAccepted {
		t.Fatalf("request SSH session = %d %s, want 202", requested.Code, requested.Body.String())
	}
	var pending struct {
		ReviewID string `json:"review_id"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(requested.Body.Bytes(), &pending); err != nil || pending.ReviewID == "" || pending.State != coreaccessreviews.StatePending {
		t.Fatalf("pending response = %#v, %v", pending, err)
	}
	if sessionsCreated != 0 {
		t.Fatalf("SSH connector opened before approval, sessions=%d", sessionsCreated)
	}
	if got := doJSONRequest(t, router, http.MethodGet, "/api/v1/access-reviews/"+pending.ReviewID, "", otherSession.AccessToken, "127.0.0.1:43210"); got.Code != http.StatusNotFound {
		t.Fatalf("other operator reads review = %d, want 404", got.Code)
	}
	queue := doJSONRequest(t, router, http.MethodGet, "/api/v1/access-reviews", "", adminSession.AccessToken, "127.0.0.1:43210")
	if queue.Code != http.StatusOK || len(reviewsPending(t, reviews)) != 1 {
		t.Fatalf("admin review queue = %d %s", queue.Code, queue.Body.String())
	}
	approved := doJSONRequest(t, router, http.MethodPost, "/api/v1/access-reviews/"+pending.ReviewID+"/approve", "", adminSession.AccessToken, "127.0.0.1:43210")
	if approved.Code != http.StatusNoContent {
		t.Fatalf("approve login review = %d %s", approved.Code, approved.Body.String())
	}
	status := doJSONRequest(t, router, http.MethodGet, "/api/v1/access-reviews/"+pending.ReviewID, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if status.Code != http.StatusOK || !containsText(status.Body.String(), `"state":"approved"`) {
		t.Fatalf("operator review status = %d %s", status.Code, status.Body.String())
	}
	// An approved old endpoint must not authorize the same asset ID after
	// configuration changes; the connector remains unopened during re-review.
	_, err = assets.Update(asset.ID, coreassets.Input{Name: asset.Name, Host: "192.0.2.21", Port: asset.Port, Username: asset.Username, HostKeyFingerprint: asset.HostKeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	changed := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if changed.Code != http.StatusAccepted || sessionsCreated != 0 {
		t.Fatalf("stale endpoint approval accepted: %d", changed.Code)
	}
	var newReview struct {
		ReviewID string `json:"review_id"`
	}
	if err := json.Unmarshal(changed.Body.Bytes(), &newReview); err != nil || newReview.ReviewID == pending.ReviewID {
		t.Fatal("changed endpoint reused old review")
	}
	if err := reviews.Resolve(newReview.ReviewID, "admin.user", true); err != nil {
		t.Fatal(err)
	}
	connected := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if connected.Code != http.StatusCreated || sessionsCreated != 1 {
		t.Fatalf("approved session = %d %s, sessions=%d", connected.Code, connected.Body.String(), sessionsCreated)
	}
	reused := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if reused.Code != http.StatusAccepted || sessionsCreated != 1 {
		t.Fatalf("consumed approval reused = %d %s, sessions=%d", reused.Code, reused.Body.String(), sessionsCreated)
	}
}

func reviewsPending(t *testing.T, store *coreaccessreviews.Store) []coreaccessreviews.Review {
	t.Helper()
	items, err := store.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func containsText(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
