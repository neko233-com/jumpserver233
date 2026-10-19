package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrandingPersistsAcrossPostgresLeaderTakeover(t *testing.T) {
	dbURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for real branding leader takeover")
	}
	namespace := fmt.Sprintf("branding-ha-%d", time.Now().UnixNano())
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	first := integrationNodeConfig(t, namespace, dir, key, freeAddress(t), freeAddress(t))
	second := integrationNodeConfig(t, namespace, dir, key, freeAddress(t), freeAddress(t))
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	done1, done2 := make(chan error, 1), make(chan error, 1)
	started2, finished1 := false, false
	t.Cleanup(func() {
		cancel1()
		cancel2()
		if !finished1 {
			select {
			case e := <-done1:
				assert.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("first branding node did not stop")
			}
		}
		if started2 {
			select {
			case e := <-done2:
				assert.NoError(t, e)
			case <-time.After(15 * time.Second):
				t.Error("second branding node did not stop")
			}
		}
		pool, e := sql.Open("pgx", dbURL)
		if !assert.NoError(t, e) {
			return
		}
		defer pool.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e = pool.ExecContext(cleanup, `DELETE FROM jms233_state_documents WHERE namespace=$1`, namespace)
		assert.NoError(t, e)
	})
	go func() { done1 <- runActiveStandby(ctx1, first) }()
	waitForHTTPStatus(t, "http://"+first.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	var imageData bytes.Buffer
	require.NoError(t, png.Encode(&imageData, image.NewNRGBA(image.Rect(0, 0, 16, 16))))
	raw := imageData.Bytes()
	input := branding.Input{Revision: 1, NameEN: "HA Operations", NameZH: "高可用运维", Theme: "forest", Accent: "#65d8a1", Logo: &raw, Icon: &raw, Mark: &raw, LoginImage: &raw, LoginTitleEN: "Welcome to HA", LoginTitleZH: "高可用登录", FooterEN: "Operations access", FooterZH: "运维入口", RegistrationLabel: "QA registration", RegistrationURL: "https://registration.example.invalid/"}
	var saved branding.Public
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "PUT", "/api/v1/settings/branding", first.AdminToken, "", input, 200), &saved))
	require.Equal(t, 2, saved.Revision)
	readImage := func(address string) []byte {
		response, e := http.Get("http://" + address + "/api/v1/branding/images/" + saved.LogoDigest)
		require.NoError(t, e)
		defer response.Body.Close()
		require.Equal(t, 200, response.StatusCode)
		body, e := io.ReadAll(response.Body)
		require.NoError(t, e)
		sum := sha256.Sum256(body)
		assert.Equal(t, saved.LogoDigest, hex.EncodeToString(sum[:]))
		return body
	}
	picture := readImage(first.Addr)
	_, e := os.Stat(filepath.Join(dir, "branding.json"))
	assert.True(t, os.IsNotExist(e), "HA branding must use shared storage")
	started2 = true
	go func() { done2 <- runActiveStandby(ctx2, second) }()
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 503, 20*time.Second)
	cancel1()
	select {
	case e := <-done1:
		finished1 = true
		require.NoError(t, e)
	case <-time.After(15 * time.Second):
		t.Fatal("branding leader did not stop")
	}
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", 200, 20*time.Second)
	var recovered branding.Public
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/branding", "", "", nil, 200), &recovered))
	assert.Equal(t, saved, recovered)
	assert.Equal(t, picture, readImage(second.Addr))
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "PUT", "/api/v1/settings/branding", second.AdminToken, "", input, 200), &recovered))
	assert.Equal(t, saved, recovered)
	var audit struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/settings/branding/audit", second.AdminToken, "", nil, 200), &audit))
	assert.Equal(t, 1, audit.Total)
}
