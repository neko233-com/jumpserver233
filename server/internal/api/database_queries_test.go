package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseAPIIdentityGrantsReviewIdempotencyAndRevocation(t *testing.T) {
	for _, engine := range []string{"postgresql", "mysql", "mariadb", "sqlserver", "clickhouse", "redis", "mongodb"} {
		t.Run(engine, func(t *testing.T) {
			root := t.TempDir()
			auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
			require.NoError(t, e)
			_, e = auth.Bootstrap("admin", bootstrapPassword)
			require.NoError(t, e)
			owner, e := auth.CreateUser("db-owner", "synthetic-db-owner-1234", coreauth.RoleOperator)
			require.NoError(t, e)
			_, e = auth.CreateUser("db-other", "synthetic-db-other-1234", coreauth.RoleOperator)
			require.NoError(t, e)
			ownerLogin, e := auth.Authenticate(owner.Username, "synthetic-db-owner-1234")
			require.NoError(t, e)
			otherLogin, e := auth.Authenticate("db-other", "synthetic-db-other-1234")
			require.NoError(t, e)
			admin, e := auth.Authenticate("admin", bootstrapPassword)
			require.NoError(t, e)
			inventory := testAssetService(t)
			assetInput := assets.Input{Name: "database QA", Host: "127.0.0.1", Username: "qadb", Password: "private-database-password", Protocol: engine}
			if engine == "postgresql" {
				assetInput.PostgreSQL = &assets.PostgreSQLInput{Database: "qa"}
			} else if engine == "redis" {
				assetInput.Redis = &assets.PostgreSQLInput{Database: "0"}
			} else if engine == "mongodb" {
				assetInput.MongoDB = &assets.PostgreSQLInput{Database: "qa", AuthDatabase: "admin"}
			} else if engine == "clickhouse" {
				assetInput.ClickHouse = &assets.PostgreSQLInput{Database: "qa"}
			} else if engine == "sqlserver" {
				assetInput.SQLServer = &assets.PostgreSQLInput{Database: "qa"}
			} else {
				assetInput.MySQL = &assets.PostgreSQLInput{Database: "qa"}
			}
			a, e := inventory.Create(assetInput)
			require.NoError(t, e)
			grantStore, e := grants.OpenStore(filepath.Join(root, "grants.json"))
			require.NoError(t, e)
			filterStore, e := commandfilters.OpenStore(filepath.Join(root, "filters.json"))
			require.NoError(t, e)
			_, e = filterStore.Create(commandfilters.Input{Name: "SQL review", Account: a.Username, UserID: owner.ID, AssetID: a.ID, Match: "regex", Pattern: "SELECT|ECHO|find", Action: "review"}, "admin")
			require.NoError(t, e)
			var calls atomic.Int32
			s, e := databasequery.Open(filepath.Join(root, "queries.json"), make([]byte, 32), nil, func(_ context.Context, _ string, _ postgresclient.Input, check func() error) (postgresclient.Result, error) {
				calls.Add(1)
				if e := check(); e != nil {
					return postgresclient.Result{}, e
				}
				v := "private-result"
				return postgresclient.Result{Rows: [][]*string{{&v}}, Transaction: "rolled_back"}, nil
			})
			require.NoError(t, e)
			defer s.Close()
			d := Dependencies{Assets: inventory, Auth: auth, Grants: grantStore, CommandFilters: filterStore, DatabaseQueries: s}
			router := NewRouter("test", d)
			session, e := s.CreateSession(databasequery.Session{Protocol: engine, UserID: owner.ID, Operator: owner.Username, AssetID: a.ID, AssetName: a.Name, Account: a.Username, Database: assets.DatabaseSettings(a).Database, ReadOnly: true, Binding: databaseRouteBinding(d, a)})
			require.NoError(t, e)
			call := func(method, path, token, dbToken string, body any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest(method, path, bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer "+token)
				r.Header.Set("X-JMS-DB-SESSION", dbToken)
				r.RemoteAddr = "127.0.0.1:1234"
				w := httptest.NewRecorder()
				router.ServeHTTP(w, r)
				return w
			}
			in := databasequery.Input{Input: postgresclient.Input{SQL: "SELECT $1::text /*private-comment*/", Parameters: []json.RawMessage{json.RawMessage(`"private-parameter"`)}, RowLimit: 10, TimeoutSeconds: 5}, RequestID: "api-db-request"}
			if engine != "postgresql" {
				in.SQL = "SELECT ? /*private-comment*/"
			}
			if engine == "sqlserver" {
				in.SQL = "SELECT @p1 /*private-comment*/"
			}
			if engine == "clickhouse" {
				in.SQL = "SELECT {p1:String} /*private-comment*/"
			}
			if engine == "redis" {
				in.SQL = `["ECHO","private-parameter"]`
				in.Parameters = nil
			}
			if engine == "mongodb" {
				in.SQL = `{"find":"private-collection","filter":{"value":"private-parameter"}}`
				in.Parameters = nil
			}
			path := "/api/v1/assets/" + a.ID + "/database-queries"
			assert.Equal(t, 403, call("POST", path, ownerLogin.AccessToken, session.Token, in).Code)
			grant, e := grantStore.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
			require.NoError(t, e)
			created := call("POST", path, ownerLogin.AccessToken, session.Token, in)
			require.Equal(t, 201, created.Code, created.Body.String())
			assert.NotContains(t, created.Body.String(), "private-")
			var j databasequery.Job
			require.NoError(t, json.Unmarshal(created.Body.Bytes(), &j))
			assert.Equal(t, "awaiting_review", j.State)
			assert.Zero(t, calls.Load())
			assert.Equal(t, 404, call("GET", "/api/v1/database-queries/"+j.ID, otherLogin.AccessToken, "", nil).Code)
			assert.Equal(t, 403, call("POST", "/api/v1/database-queries/"+j.ID+"/review", ownerLogin.AccessToken, "", map[string]bool{"approve": true}).Code)
			require.NoError(t, grantStore.Delete(grant.ID))
			reviewed := call("POST", "/api/v1/database-queries/"+j.ID+"/review", admin.AccessToken, "", map[string]bool{"approve": true})
			require.Equal(t, 204, reviewed.Code)
			require.Eventually(t, func() bool { r, _ := s.Get(j.ID, owner.ID, false); return r.State == "failed" }, time.Second, 5*time.Millisecond)
			assert.Zero(t, calls.Load())
			grant, e = grantStore.Create(grants.Input{UserID: owner.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
			require.NoError(t, e)
			in.RequestID = "api-db-success"
			created = call("POST", path, ownerLogin.AccessToken, session.Token, in)
			require.Equal(t, 201, created.Code)
			require.NoError(t, json.Unmarshal(created.Body.Bytes(), &j))
			require.Equal(t, 204, call("POST", "/api/v1/database-queries/"+j.ID+"/review", admin.AccessToken, "", map[string]bool{"approve": true}).Code)
			require.Eventually(t, func() bool { r, _ := s.Get(j.ID, owner.ID, false); return r.State == "completed" }, time.Second, 5*time.Millisecond)
			details := call("GET", "/api/v1/database-queries/"+j.ID, ownerLogin.AccessToken, "", nil)
			assert.Contains(t, details.Body.String(), "private-result")
			assert.NotContains(t, details.Body.String(), "private-parameter")
			assert.NotContains(t, details.Body.String(), "private-database-password")
			assert.Equal(t, "private, no-store", details.Header().Get("Cache-Control"))
			auditor := call("GET", "/api/v1/database-queries/"+j.ID, admin.AccessToken, "", nil)
			assert.NotContains(t, auditor.Body.String(), "private-result")
			again := call("POST", path, ownerLogin.AccessToken, session.Token, in)
			assert.Equal(t, 201, again.Code)
			assert.Contains(t, again.Body.String(), j.ID)
			assert.EqualValues(t, 1, calls.Load())
			require.NoError(t, grantStore.Delete(grant.ID))
			assert.Equal(t, 403, call("GET", "/api/v1/database-queries/"+j.ID, ownerLogin.AccessToken, "", nil).Code)
			assert.Equal(t, 404, call("POST", path, otherLogin.AccessToken, session.Token, in).Code)
			assert.Equal(t, 403, call("GET", "/api/v1/database-queries?pending_reviews=true", ownerLogin.AccessToken, "", nil).Code)
		})
	}
}
func TestRealDatabaseSessionRequiresSeparateLoginApprovalAndRunsQuery(t *testing.T) {
	target, secret := postgresfixture.Load(t)
	inventory := testAssetService(t)
	required := true
	a, e := inventory.Create(assets.Input{Name: "PG TLS", Protocol: "postgresql", Host: target.Host, Port: target.Port, Username: target.Username, Password: secret.Password, LoginReviewRequired: &required, PostgreSQL: &assets.PostgreSQLInput{Database: target.Database, RootCAPEM: target.RootCAPEM, ServerName: target.ServerName}})
	require.NoError(t, e)
	root := t.TempDir()
	auth, e := coreauth.OpenService(filepath.Join(root, "users.json"))
	require.NoError(t, e)
	_, e = auth.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	u, e := auth.CreateUser("db-user", "synthetic-db-user-1234", coreauth.RoleOperator)
	require.NoError(t, e)
	login, e := auth.Authenticate(u.Username, "synthetic-db-user-1234")
	require.NoError(t, e)
	g, e := grants.OpenStore(filepath.Join(root, "grants.json"))
	require.NoError(t, e)
	_, e = g.Create(grants.Input{UserID: u.ID, AssetID: a.ID, Account: a.Username, Actions: []string{"connect"}}, "admin")
	require.NoError(t, e)
	reviews, e := accessreviews.OpenStore(filepath.Join(root, "reviews.json"))
	require.NoError(t, e)
	s, e := databasequery.Open(filepath.Join(root, "queries.json"), make([]byte, 32), nil, inventory.QueryPostgreSQL)
	require.NoError(t, e)
	defer s.Close()
	router := NewRouter("test", Dependencies{Assets: inventory, Auth: auth, Grants: g, AccessReviews: reviews, DatabaseQueries: s})
	path := "/api/v1/assets/" + a.ID + "/database-sessions"
	r := doJSONRequest(t, router, "POST", path, "", login.AccessToken, "127.0.0.1:12")
	require.Equal(t, 202, r.Code, r.Body.String())
	var review struct {
		ID string `json:"review_id"`
	}
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &review))
	item, e := reviews.Get(review.ID)
	require.NoError(t, e)
	assert.Equal(t, accessreviews.ActionDatabase, item.Action)
	require.NoError(t, reviews.Resolve(item.ID, "admin", true))
	r = doJSONRequest(t, router, "POST", path, "", login.AccessToken, "127.0.0.1:12")
	require.Equal(t, 201, r.Code, r.Body.String())
	assert.NotContains(t, r.Body.String(), secret.Password)
	var session databasequery.SessionResponse
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &session))
	payload := `{"sql":"SELECT current_database()","request_id":"real-api-query","row_limit":5,"timeout_seconds":5}`
	request := httptest.NewRequest("POST", "/api/v1/assets/"+a.ID+"/database-queries", bytes.NewBufferString(payload))
	request.Header.Set("Authorization", "Bearer "+login.AccessToken)
	request.Header.Set("X-JMS-DB-SESSION", session.Token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	require.Equal(t, 201, w.Code, w.Body.String())
	var job databasequery.Job
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &job))
	require.Eventually(t, func() bool { result, _ := s.Get(job.ID, u.ID, false); return result.State == "completed" }, 5*time.Second, 10*time.Millisecond)
	result, e := s.Get(job.ID, u.ID, false)
	require.NoError(t, e)
	require.NotNil(t, result.Result)
	assert.Equal(t, "qa", *result.Result.Rows[0][0])
}
