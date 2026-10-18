// Package webui serves an optional production SPA beside the API and gateway.
package webui

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

type Handler struct {
	root  *os.Root
	api   http.Handler
	files http.Handler
}

// Open confines all file access, including symlinks, to the frontend directory.
func Open(api http.Handler, directory string) (*Handler, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open frontend: %w", err)
	}
	info, err := fs.Stat(root.FS(), "index.html")
	if err != nil || !info.Mode().IsRegular() {
		root.Close()
		return nil, fmt.Errorf("frontend requires a regular index.html")
	}
	return &Handler{root: root, api: api, files: http.FileServerFS(root.FS())}, nil
}

func (h *Handler) Close() error { return h.root.Close() }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "api" || strings.HasPrefix(name, "api/") || name == "ws" || strings.HasPrefix(name, "ws/") {
		h.api.ServeHTTP(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || strings.Contains(part, "\\") {
			http.NotFound(w, r)
			return
		}
	}
	if name == "" {
		name = "index.html"
	}
	info, err := fs.Stat(h.root.FS(), name)
	if err != nil || !info.Mode().IsRegular() {
		if path.Ext(name) != "" || strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	w.Header().Set("Cache-Control", "no-cache")
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	// ServeFile redirects /index.html to /; rewrite to / so SPA fallback works.
	copy := r.Clone(r.Context())
	url := *r.URL
	copy.URL = &url
	copy.URL.Path = "/" + name
	if name == "index.html" {
		copy.URL.Path = "/"
	}
	h.files.ServeHTTP(w, copy)
}
