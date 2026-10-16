package sessionclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestCreateSessionReturnsTypedLoginReviewPendingError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"review_id": "access-review-test", "state": "pending"})
	}))
	defer server.Close()
	client, err := New(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateSession(context.Background(), gateway.CreateRequest{AssetID: "asset-1", Cols: 80, Rows: 24})
	var pending *AccessReviewPendingError
	if err == nil || !errors.As(err, &pending) || pending.ReviewID != "access-review-test" {
		t.Fatalf("CreateSession error = %#v, pending = %#v", err, pending)
	}
}

func TestGetAccessReviewReadsOwnerVisibleState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access-reviews/access-review-test" || r.Method != http.MethodGet {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "access-review-test", "state": "approved"})
	}))
	defer server.Close()
	client, err := New(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	review, err := client.GetAccessReview(context.Background(), "access-review-test")
	if err != nil || review.State != "approved" {
		t.Fatalf("GetAccessReview = %#v, %v", review, err)
	}
}
