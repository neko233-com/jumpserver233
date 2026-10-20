package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperationDirectoryAdmissionDefersOnlyProvableUnknownDirectories(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, err)
	_, err = identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, err)
	owner, err := identities.CreateUser("directory-owner", "synthetic-directory-owner-233", coreauth.RoleOperator)
	require.NoError(t, err)
	inventory := testAssetService(t)
	rooted, err := inventory.Create(assets.Input{Name: "Rooted", Host: "127.0.0.1", Port: 1, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint(), SSHWorkspace: "/srv/work"})
	require.NoError(t, err)
	unrooted, err := inventory.Create(assets.Input{Name: "Unrooted", Host: "127.0.0.1", Port: 1, Username: "ops", Password: "synthetic-only", HostKeyFingerprint: validTestFingerprint()})
	require.NoError(t, err)
	d := Dependencies{Auth: identities, Assets: inventory}
	for _, tc := range []struct {
		name, asset, directory            string
		allowed, unknown, forbidden, want bool
	}{
		{"verified-later", rooted.ID, "/srv/work/deploy", false, true, false, true},
		{"root-default", rooted.ID, "", false, true, false, true},
		{"known-denial", rooted.ID, "/srv/work/deploy", false, false, false, false},
		{"allowed", rooted.ID, "/srv/work/deploy", true, false, false, true},
		{"outside", rooted.ID, "/srv/other", true, false, false, false},
		{"sibling-prefix", rooted.ID, "/srv/work-other", false, true, false, false},
		{"unconfined", unrooted.ID, "/srv/work/deploy", true, false, false, false},
		{"unknown-unconfined", unrooted.ID, "", false, true, false, false},
		{"current-permission-denied", rooted.ID, "/srv/work/deploy", false, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := operations.Plan{OwnerID: owner.ID, PlanInput: operations.PlanInput{AssetIDs: []string{tc.asset}, Command: "pwd", WorkingDirectory: tc.directory}}
			for _, scheduled := range []bool{false, true} {
				authorize := func(u coreauth.User, id, command string, origin accesspolicies.Origin) (string, string, commandfilters.Decision, int) {
					assert.Equal(t, owner.ID, u.ID)
					assert.Equal(t, tc.asset, id)
					if scheduled {
						assert.Equal(t, "scheduled_exec", origin.Method)
					}
					status := http.StatusOK
					if tc.forbidden {
						status = http.StatusForbidden
					}
					return "", "ops", commandfilters.Decision{Allowed: tc.allowed, DirectoryRequired: tc.unknown}, status
				}
				assert.Equal(t, tc.want, authorizeOperationOwner(d, p, authorize, scheduled))
			}
		})
	}
	assert.False(t, operationDirectoryProofPossible(Dependencies{}, rooted.ID, "/srv/work"))
	assert.Error(t, validateOperationDirectoryAsset(d, "missing", "/srv/work"))
	assert.NoError(t, validateOperationDirectoryAsset(d, rooted.ID, "/srv/work/deploy"))
}
