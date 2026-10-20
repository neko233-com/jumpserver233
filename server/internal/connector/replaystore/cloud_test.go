package replaystore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDigest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func reference256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func reference1(key []byte, value string) []byte {
	h := hmac.New(sha1.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func testCloudConfig(provider, endpoint, root string) CloudConfig {
	return CloudConfig{Provider: provider, Endpoint: endpoint, RootCAPEM: root, PathStyle: true, Region: "cn-test-1", Bucket: "qa-bucket", AccessKeyID: "SYNTHETICAKID233", SecretAccessKey: "synthetic-replay-storage-secret-233", SessionToken: "synthetic-token"}
}

func TestReplayStorageProviderSignaturesMatchExplicitCanonicalRequests(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	stamp := "20260102T030405Z"
	day := "20260102"
	body := []byte("opaque ciphertext")
	hash := testDigest(body)
	t.Run("AWS v4", func(t *testing.T) {
		cfg := testCloudConfig("s3", "https://s3.example.invalid", "")
		c := &Cloud{config: cfg}
		r, e := http.NewRequest("GET", "https://qa-bucket.s3.example.invalid/test.txt", nil)
		require.NoError(t, e)
		r.Header.Set("Range", "bytes=0-9")
		c.sign(r, "test.txt", emptySHA256, at)
		canonical := "GET\n/test.txt\n\nhost:qa-bucket.s3.example.invalid\nrange:bytes=0-9\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:" + stamp + "\nx-amz-security-token:synthetic-token\n\nhost;range;x-amz-content-sha256;x-amz-date;x-amz-security-token\n" + emptySHA256
		key := []byte("AWS4" + cfg.SecretAccessKey)
		for _, part := range []string{day, cfg.Region, "s3", "aws4_request"} {
			key = reference256(key, part)
		}
		scope := day + "/" + cfg.Region + "/s3/aws4_request"
		expected := hex.EncodeToString(reference256(key, "AWS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+testDigest([]byte(canonical))))
		assert.Equal(t, "AWS4-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+scope+", SignedHeaders=host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature="+expected, r.Header.Get("Authorization"))
	})
	t.Run("OSS v4", func(t *testing.T) {
		cfg := testCloudConfig("oss", "https://oss.example.invalid", "")
		c := &Cloud{config: cfg}
		r, e := http.NewRequest("PUT", "https://qa-bucket.oss.example.invalid/namespace/object.enc", bytes.NewReader(body))
		require.NoError(t, e)
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Oss-Forbid-Overwrite", "true")
		c.sign(r, "namespace/object.enc", hash, at)
		canonical := "PUT\n/qa-bucket/namespace/object.enc\n\ncontent-type:application/octet-stream\nhost:qa-bucket.oss.example.invalid\nx-oss-content-sha256:UNSIGNED-PAYLOAD\nx-oss-date:" + stamp + "\nx-oss-forbid-overwrite:true\nx-oss-security-token:synthetic-token\n\nhost\nUNSIGNED-PAYLOAD"
		key := []byte("aliyun_v4" + cfg.SecretAccessKey)
		for _, part := range []string{day, cfg.Region, "oss", "aliyun_v4_request"} {
			key = reference256(key, part)
		}
		scope := day + "/" + cfg.Region + "/oss/aliyun_v4_request"
		signature := hex.EncodeToString(reference256(key, "OSS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+testDigest([]byte(canonical))))
		assert.Equal(t, "OSS4-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+scope+",AdditionalHeaders=host,Signature="+signature, r.Header.Get("Authorization"))
	})
	t.Run("OBS headers", func(t *testing.T) {
		cfg := testCloudConfig("obs", "https://obs.example.invalid", "")
		c := &Cloud{config: cfg}
		r, e := http.NewRequest("PUT", "https://qa-bucket.obs.example.invalid/namespace/object.enc", bytes.NewReader(body))
		require.NoError(t, e)
		r.Header.Set("Content-Type", "application/octet-stream")
		c.sign(r, "namespace/object.enc", hash, at)
		expected := "PUT\n\napplication/octet-stream\nFri, 02 Jan 2026 03:04:05 GMT\nx-obs-security-token:synthetic-token\n/qa-bucket/namespace/object.enc"
		assert.Equal(t, "OBS "+cfg.AccessKeyID+":"+base64.StdEncoding.EncodeToString(reference1([]byte(cfg.SecretAccessKey), expected)), r.Header.Get("Authorization"))
	})
	t.Run("COS token and canonical headers", func(t *testing.T) {
		cfg := testCloudConfig("cos", "https://cos.example.invalid", "")
		c := &Cloud{config: cfg}
		r, e := http.NewRequest("PUT", "https://qa-bucket.cos.example.invalid/namespace/object.enc", bytes.NewReader(body))
		require.NoError(t, e)
		r.Header.Set("Content-Type", "application/octet-stream")
		c.sign(r, "namespace/object.enc", hash, at)
		signature := r.Header.Get("Authorization")
		window := strconv.FormatInt(at.Add(-time.Minute).Unix(), 10) + ";" + strconv.FormatInt(at.Add(10*time.Minute).Unix(), 10)
		requestString := "put\n/namespace/object.enc\n\ncontent-type=application%2Foctet-stream&host=qa-bucket.cos.example.invalid&x-cos-security-token=synthetic-token\n"
		reqHash := sha1.Sum([]byte(requestString))
		signKey := hex.EncodeToString(reference1([]byte(cfg.SecretAccessKey), window))
		expected := hex.EncodeToString(reference1([]byte(signKey), "sha1\n"+window+"\n"+hex.EncodeToString(reqHash[:])+"\n"))
		assert.Equal(t, "q-sign-algorithm=sha1&q-ak="+cfg.AccessKeyID+"&q-sign-time="+window+"&q-key-time="+window+"&q-header-list=content-type;host;x-cos-security-token&q-url-param-list=&q-signature="+expected, signature)
		assert.Contains(t, signature, "q-header-list=content-type;host;x-cos-security-token&")
		assert.Contains(t, signature, "q-ak="+cfg.AccessKeyID)
		assert.Equal(t, cfg.SessionToken, r.Header.Get("X-Cos-Security-Token"))
		assert.NotContains(t, signature, cfg.SecretAccessKey)
		assert.NotContains(t, signature, cfg.SessionToken)
	})
}

func TestReplayStorageCloudTLSOpaqueObjectRoundTripAndExclusiveRetries(t *testing.T) {
	for _, provider := range []string{"s3", "oss", "cos", "obs"} {
		t.Run(provider, func(t *testing.T) {
			var mu sync.Mutex
			objects := map[string][]byte{}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				assert.Contains(t, r.URL.Path, "/qa-bucket/")
				auth := r.Header.Get("Authorization")
				prefix := map[string]string{"s3": "AWS4-HMAC-SHA256 ", "oss": "OSS4-HMAC-SHA256 ", "cos": "q-sign-algorithm=sha1&", "obs": "OBS "}[provider]
				assert.True(t, strings.HasPrefix(auth, prefix))
				assert.NotContains(t, auth, "synthetic-replay-storage-secret-233")
				mu.Lock()
				defer mu.Unlock()
				if r.Method == "PUT" {
					conditional := map[string]string{"s3": "If-None-Match", "oss": "X-Oss-Forbid-Overwrite", "cos": "X-Cos-Forbid-Overwrite", "obs": "X-Obs-Forbid-Overwrite"}[provider]
					value := "true"
					if provider == "s3" {
						value = "*"
					}
					assert.Equal(t, value, r.Header.Get(conditional))
					if _, ok := objects[r.URL.Path]; ok {
						w.WriteHeader(412)
						return
					}
					raw, e := io.ReadAll(io.LimitReader(r.Body, 1024))
					assert.NoError(t, e)
					objects[r.URL.Path] = raw
					w.WriteHeader(200)
					return
				}
				raw, ok := objects[r.URL.Path]
				if !ok {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			c, e := NewCloud(testCloudConfig(provider, server.URL, roots))
			require.NoError(t, e)
			defer c.Close()
			ctx := context.Background()
			data := []byte("JMSREC1\nopaque encrypted fixture")
			key := "namespace/object.enc"
			missing, e := c.Get(ctx, key)
			assert.Nil(t, missing)
			assert.ErrorIs(t, e, ErrNotFound)
			require.NoError(t, c.Put(ctx, key, bytes.NewReader(data), int64(len(data)), testDigest(data)))
			require.ErrorIs(t, c.Put(ctx, key, bytes.NewReader(data), int64(len(data)), testDigest(data)), ErrExists)
			r, e := c.Get(ctx, key)
			require.NoError(t, e)
			actual, e := io.ReadAll(r)
			require.NoError(t, e)
			require.NoError(t, r.Close())
			assert.Equal(t, data, actual)
			count := calls.Load()
			assert.ErrorIs(t, c.Put(ctx, "../escape", bytes.NewReader(data), int64(len(data)), testDigest(data)), ErrInvalid)
			assert.Equal(t, count, calls.Load())
			require.ErrorIs(t, c.Put(ctx, "namespace/wrong-hash.enc", bytes.NewReader(data), int64(len(data)), strings.Repeat("a", 64)), ErrIntegrity)
		})
	}
}

func TestReplayStorageCloudValidationTLSAndRedirectRefusal(t *testing.T) {
	base := testCloudConfig("s3", "https://s3.example.invalid", "")
	for _, mutate := range []func(*CloudConfig){func(c *CloudConfig) { c.Endpoint = "http://192.0.2.1" }, func(c *CloudConfig) { c.Endpoint = "https://user:secret@example.invalid" }, func(c *CloudConfig) { c.RootCAPEM = "not a certificate" }, func(c *CloudConfig) { c.Bucket = "../other" }, func(c *CloudConfig) { c.SecretAccessKey = "bad\r\nvalue" }, func(c *CloudConfig) { c.Provider = "unknown" }} {
		in := base
		mutate(&in)
		_, e := NewCloud(in)
		assert.ErrorIs(t, e, ErrInvalid)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://127.0.0.1:1/credential-leak")
		w.WriteHeader(302)
	}))
	defer server.Close()
	cfg := testCloudConfig("s3", server.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	c, e := NewCloud(cfg)
	require.NoError(t, e)
	defer c.Close()
	_, e = c.Get(context.Background(), "namespace/object.enc")
	assert.ErrorIs(t, e, ErrUnavailable)
	assert.NotContains(t, e.Error(), server.URL)
	cfg.RootCAPEM = ""
	untrusted, e := NewCloud(cfg)
	require.NoError(t, e)
	defer untrusted.Close()
	_, e = untrusted.Get(context.Background(), "namespace/object.enc")
	assert.ErrorIs(t, e, ErrUnavailable)
}
