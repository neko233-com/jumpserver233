package samlclient_test

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/samlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/identityscope"
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSAMLSourceScopedACSMetadataAndSignedAudience(t *testing.T) {
	provider, e := samlprovider.New("https://idp.example.invalid")
	require.NoError(t, e)
	key, e := samlclient.GenerateKey()
	require.NoError(t, e)
	prefix := identityscope.Prefix("idp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cfg := samlclient.Config{EntityID: "https://console.example.invalid/source-a", ACSURL: "https://console.example.invalid" + prefix + samlclient.ACSPath, MetadataXML: provider.Metadata()}
	client, e := samlclient.New(cfg, key, prefix)
	require.NoError(t, e)
	_, _, e = client.Begin("scoped-state")
	require.NoError(t, e)
	metadata, e := client.Metadata()
	require.NoError(t, e)
	assert.Contains(t, string(metadata), prefix+samlclient.ACSPath)
	assert.Contains(t, string(metadata), `entityID="`+cfg.EntityID+`"`)
	_, e = samlclient.New(cfg, key)
	assert.ErrorIs(t, e, samlclient.ErrConfig)
	_, e = samlclient.New(cfg, key, identityscope.Prefix("idp-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	assert.ErrorIs(t, e, samlclient.ErrConfig)
}
