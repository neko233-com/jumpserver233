package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStandaloneUIAndAPIBoundaries(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>JumpServer233</html>"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app-123.js"), []byte("console.log(1)"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("private"), 0600))
	h, err := Open(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, h.Close()) })
	for _, test := range []struct {
		method, path string
		status       int
		body, cache  string
	}{
		{"GET", "/", 200, "JumpServer233", "no-cache"},
		{"GET", "/login", 200, "JumpServer233", "no-cache"},
		{"GET", "/console/agent-audit", 200, "JumpServer233", "no-cache"},
		{"GET", "/assets/app-123.js", 200, "console.log", "public, max-age=31536000, immutable"},
		{"HEAD", "/login", 200, "", "no-cache"},
		{"GET", "/assets/missing.js", 404, "", ""},
		{"GET", "/assets/missing", 404, "", ""},
		{"GET", "/.env", 404, "", ""},
		{"GET", "/%2e%2e/private.txt", 404, "", ""},
		{"GET", "/api/missing", 418, "", ""},
		{"GET", "/ws/ssh", 418, "", ""},
		{"POST", "/login", 405, "", ""},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
			require.Equal(t, test.status, w.Code)
			if test.body != "" {
				require.Contains(t, w.Body.String(), test.body)
			}
			if test.cache != "" {
				require.Equal(t, test.cache, w.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestFrontendMustExistAndSymlinkCannotEscape(t *testing.T) {
	_, err := Open(nil, t.TempDir())
	require.Error(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("UI"), 0600))
	outside := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outside, []byte("outside secret"), 0600))
	if err := os.Symlink(outside, filepath.Join(dir, "escape.txt")); err != nil {
		t.Skip("symlink unavailable")
	}
	h, err := Open(nil, dir)
	require.NoError(t, err)
	defer h.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/escape.txt", nil))
	require.Equal(t, 404, w.Code)
	require.NotContains(t, w.Body.String(), "outside secret")
}
