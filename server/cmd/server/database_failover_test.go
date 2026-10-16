package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/testsupport/clickhousefixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/mysqlfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/nosqlfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/postgresfixture"
	"github.com/neko233-com/jumpserver233/server/testsupport/sqlserverfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
)

type databaseFailoverProof struct{ Asset, Session, Completed, Pending string }

func databaseHARequest(t *testing.T, address, method, path, token, org, session string, input any, status int) []byte {
	t.Helper()
	raw, e := json.Marshal(input)
	require.NoError(t, e)
	r, e := http.NewRequest(method, "http://"+address+path, bytes.NewReader(raw))
	require.NoError(t, e)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	if org != "" {
		r.Header.Set("X-JMS-ORG", org)
	}
	if session != "" {
		r.Header.Set("X-JMS-DB-SESSION", session)
	}
	response, e := http.DefaultClient.Do(r)
	require.NoError(t, e)
	defer response.Body.Close()
	var out json.RawMessage
	if response.StatusCode != 204 {
		require.NoError(t, json.NewDecoder(response.Body).Decode(&out))
	}
	require.Equal(t, status, response.StatusCode, string(out))
	return out
}
func prepareDatabaseFailover(t *testing.T, address, token, org string) *databaseFailoverProof {
	return prepareDatabaseFailoverEngine(t, address, token, org, "postgresql")
}
func prepareDatabaseFailoverEngine(t *testing.T, address, token, org, engine string) *databaseFailoverProof {
	var target sqlclient.Target
	var secret sqlclient.Credentials
	if engine == "postgresql" {
		if os.Getenv("JMS_TEST_POSTGRES_FIXTURE_URL") == "" {
			return nil
		}
		target, secret = postgresfixture.Load(t)
	} else if engine == "redis" || engine == "mongodb" {
		if os.Getenv("JMS_TEST_"+strings.ToUpper(engine)+"_FIXTURE_URL") == "" {
			return nil
		}
		target, secret = nosqlfixture.Load(t, engine)
	} else if engine == "clickhouse" {
		if os.Getenv("JMS_TEST_CLICKHOUSE_FIXTURE_URL") == "" {
			return nil
		}
		target, secret = clickhousefixture.Load(t)
	} else if engine == "sqlserver" {
		if os.Getenv("JMS_TEST_SQLSERVER_FIXTURE_URL") == "" {
			return nil
		}
		target, secret = sqlserverfixture.Load(t)
	} else {
		if os.Getenv("JMS_TEST_"+strings.ToUpper(engine)+"_FIXTURE_URL") == "" {
			return nil
		}
		target, secret = mysqlfixture.Load(t, engine)
	}

	var asset assets.Asset
	config := &assets.PostgreSQLInput{AuthDatabase: target.AuthDatabase, Database: target.Database, ServerName: target.ServerName, RootCAPEM: target.RootCAPEM}
	input := assets.Input{Protocol: engine, Name: "HA " + engine, Host: target.Host, Port: target.Port, Username: target.Username, Password: secret.Password}
	if engine == "postgresql" {
		input.PostgreSQL = config
	} else if engine == "redis" {
		input.Redis = config
	} else if engine == "mongodb" {
		input.MongoDB = config
	} else if engine == "clickhouse" {
		input.ClickHouse = config
	} else if engine == "sqlserver" {
		input.SQLServer = config
	} else {
		input.MySQL = config
	}
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets", token, org, "", input, 201), &asset))
	var session databasequery.SessionResponse
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets/"+asset.ID+"/database-sessions", token, org, "", nil, 201), &session))
	submit := func(sql, id string) databasequery.Job {
		var job databasequery.Job
		require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "POST", "/api/v1/assets/"+asset.ID+"/database-queries", token, org, session.Token, map[string]any{"sql": sql, "request_id": engine + "-" + id, "row_limit": 5, "timeout_seconds": 5}, 201), &job))
		return job
	}
	query := "SELECT current_database()"
	if engine != "postgresql" {
		query = "SELECT DATABASE()"
	}
	if engine == "sqlserver" {
		query = "SELECT DB_NAME()"
	}
	if engine == "clickhouse" {
		query = "SELECT currentDatabase()"
	}
	if engine == "redis" {
		query = `["PING"]`
	}
	if engine == "mongodb" {
		query = `{"ping":1}`
	}
	completed := submit(query, "ha-database-complete")
	require.Eventually(t, func() bool {
		var r databasequery.Response
		_ = json.Unmarshal(databaseHARequest(t, address, "GET", "/api/v1/database-queries/"+completed.ID, token, org, "", nil, 200), &r)
		return r.State == "completed"
	}, 5*time.Second, 20*time.Millisecond)
	databaseHARequest(t, address, "POST", "/api/v1/command-filters", token, org, "", map[string]any{"name": "HA database review", "account": target.Username, "asset_id": asset.ID, "match": "contains", "pattern": "ha-pending-database", "action": "review"}, 201)
	pendingSQL := "SELECT 'ha-pending-database'"
	if engine == "redis" {
		pendingSQL = `["ECHO","ha-pending-database"]`
	}
	if engine == "mongodb" {
		pendingSQL = `{"aggregate":1,"pipeline":[{"$documents":[{"message":"ha-pending-database"}]}],"cursor":{}}`
	}
	pending := submit(pendingSQL, "ha-database-await-review")
	require.Equal(t, "awaiting_review", pending.State)
	return &databaseFailoverProof{Asset: asset.ID, Session: session.Token, Completed: completed.ID, Pending: pending.ID}
}
func verifyDatabaseFailover(t *testing.T, address, token, org string, p *databaseFailoverProof) {
	if p == nil {
		return
	}
	var completed databasequery.Response
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "GET", "/api/v1/database-queries/"+p.Completed, token, org, "", nil, 200), &completed))
	assert.Equal(t, "completed", completed.State)
	assert.Nil(t, completed.Result)
	assert.Empty(t, completed.Summary.Columns)
	assert.Empty(t, completed.Summary.Rows)
	assert.False(t, completed.ResultAvailable)
	var pending databasequery.Response
	require.NoError(t, json.Unmarshal(databaseHARequest(t, address, "GET", "/api/v1/database-queries/"+p.Pending, token, org, "", nil, 200), &pending))
	assert.Contains(t, []string{"cancelled", "interrupted"}, pending.State)
	databaseHARequest(t, address, "POST", "/api/v1/assets/"+p.Asset+"/database-queries", token, org, p.Session, map[string]any{"sql": "SELECT 1", "request_id": "ha-stale-db-session", "row_limit": 1, "timeout_seconds": 5}, 404)
	databaseHARequest(t, address, "POST", "/api/v1/assets/"+p.Asset+"/database-sessions", token, org, "", nil, 201)
	databaseHARequest(t, address, "GET", "/api/v1/database-queries/"+p.Completed, token, "", "", nil, 404)
}
