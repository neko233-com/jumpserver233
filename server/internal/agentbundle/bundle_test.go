package agentbundle

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBundleWasGeneratedFromCurrentNativeSources(t *testing.T) {
	root, e := filepath.Abs("../..")
	require.NoError(t, e)
	expected, e := SourceDigest(root)
	require.NoError(t, e)
	raw, e := files.ReadFile("artifacts/manifest.json")
	require.NoError(t, e)
	var m Manifest
	require.NoError(t, json.Unmarshal(raw, &m))
	require.Equal(t, expected, m.SourceSHA256, "run go generate ./internal/agentbundle after source changes")
}

func TestEmbeddedNativeAgentsMatchManifestAndELFArchitecture(t *testing.T) {
	for _, platform := range []string{"linux-amd64", "linux-arm64"} {
		t.Run(platform, func(t *testing.T) {
			binary, e := Get(platform)
			require.NoError(t, e, "run go generate ./internal/agentbundle")
			require.Equal(t, "3", binary.Version)
			require.Len(t, binary.SHA256, 64)
			require.Greater(t, len(binary.Data), 1024)
		})
	}
	_, e := Get("linux-386")
	require.ErrorIs(t, e, ErrUnavailable)
}
