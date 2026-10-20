package enterpriseoauth

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func cachedConfig() Config {
	return Normalize(Config{Provider: "wecom", ClientID: "synthetic-corp", AgentID: "10001", CallbackURL: "https://console.example.invalid/callback"})
}
func TestEnterpriseOAuthCacheSingleFlightExpirationAndSecretRotation(t *testing.T) {
	var calls atomic.Int32
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	client := NewClientWithTransport(func(Config) (http.RoundTripper, func(), error) {
		return roundTrip(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"errcode":0,"access_token":"synthetic-app-token","expires_in":7200}`))}, nil
		}), func() {}, nil
	})
	client.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	c := cachedConfig()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- client.Check(context.Background(), c, "synthetic-secret-a") }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	assert.Equal(t, int32(1), calls.Load())
	require.NoError(t, client.Check(t.Context(), c, "synthetic-secret-b"))
	assert.Equal(t, int32(2), calls.Load())
	clock.Add(7200)
	require.NoError(t, client.Check(t.Context(), c, "synthetic-secret-b"))
	assert.Equal(t, int32(3), calls.Load())
}
func TestEnterpriseOAuthRejectsRedirectDuplicateOversizeAndRedactsErrors(t *testing.T) {
	for _, body := range []string{`{"errcode":0,"errcode":0,"access_token":"synthetic-token","expires_in":7200}`, strings.Repeat(" ", 131073), `{"errcode":0,"access_token":"bad\nheader","expires_in":7200}`} {
		client := NewClientWithTransport(func(Config) (http.RoundTripper, func(), error) {
			return roundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}), func() {}, nil
		})
		e := client.Check(t.Context(), cachedConfig(), "synthetic-secret")
		require.Error(t, e)
		assert.NotContains(t, e.Error(), body)
		assert.NotContains(t, e.Error(), "synthetic-secret")
	}
	calls := 0
	client := NewClientWithTransport(func(Config) (http.RoundTripper, func(), error) {
		return roundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://untrusted.invalid/token"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}), func() {}, nil
	})
	require.Error(t, client.Check(t.Context(), cachedConfig(), "synthetic-secret"))
	assert.Equal(t, 1, calls)
}
