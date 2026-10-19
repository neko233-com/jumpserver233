package commandfilters

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandDirectoryRulesRequireProofAndMatchCanonicalPaths(t *testing.T) {
	for _, mode := range []string{MatchExact, DirectoryTree, MatchRegex} {
		t.Run(mode, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "filters.json")
			s, err := OpenStore(file)
			require.NoError(t, err)
			pattern := "/srv/work/app"
			if mode == MatchRegex {
				pattern = `/srv/work/app(?:/releases/[0-9]+)?`
			}
			_, err = s.Create(Input{Name: "directory review", Account: "ops", Match: MatchExact, Pattern: "touch receipt", Action: ActionReview, DirectoryMatch: mode, DirectoryPattern: pattern}, "admin")
			require.NoError(t, err)
			s, err = OpenStore(file)
			require.NoError(t, err)
			scope := Scope{Account: "ops", Directory: "/srv/work/app"}
			unknown := s.Decide(scope, "touch receipt", true, time.Now())
			assert.Equal(t, ActionDeny, unknown.Action)
			assert.True(t, unknown.DirectoryRequired)
			scope.DirectoryVerified = true
			match := s.Decide(scope, "touch receipt", true, time.Now())
			assert.Equal(t, ActionReview, match.Action)
			assert.False(t, match.DirectoryRequired)
			assert.Equal(t, unknown.PolicyKey, match.PolicyKey)
			scope.Directory = "/srv/work/app/releases/12"
			child := s.Decide(scope, "touch receipt", true, time.Now())
			assert.Equal(t, mode != MatchExact, child.Action == ActionReview)
			for _, directory := range []string{"/srv/work/app-other", "/other/srv/work/app"} {
				scope.Directory = directory
				assert.True(t, s.Decide(scope, "touch receipt", true, time.Now()).Allowed)
			}
			scope.Directory = "/srv/work/app/../app"
			assert.True(t, s.Decide(scope, "touch receipt", true, time.Now()).DirectoryRequired)
			assert.True(t, s.Decide(Scope{Account: "ops"}, "pwd", true, time.Now()).Allowed)
			assert.Equal(t, ActionDeny, s.Decide(scope, "touch receipt; pwd", false, time.Now()).Action)
		})
	}
}

func TestCommandDirectoryValidationPriorityAndPolicyRevision(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "rules"))
	require.NoError(t, err)
	for _, pair := range [][2]string{{"", "/srv/a"}, {"exact", ""}, {"contains", "/srv/a"}, {"tree", "relative"}, {"exact", "/srv/a/"}, {"regex", "["}, {"regex", "x\n"}} {
		_, err = s.Create(Input{Name: "bad", Account: "*", Match: MatchExact, Pattern: "pwd", Action: ActionAllow, DirectoryMatch: pair[0], DirectoryPattern: pair[1]}, "admin")
		require.ErrorIs(t, err, ErrInvalidInput)
	}
	scope := Scope{Account: "ops", Directory: "/srv/a", DirectoryVerified: true}
	before := s.Decide(scope, "pwd", true, time.Now())
	r, err := s.Create(Input{Name: "approved name", Account: "*", Match: MatchExact, Pattern: "pwd", Action: ActionReview, DirectoryMatch: MatchExact, DirectoryPattern: "/srv/a", Priority: 10}, "admin")
	require.NoError(t, err)
	review := s.Decide(scope, "pwd", true, time.Now())
	assert.NotEqual(t, before.PolicyKey, review.PolicyKey)
	require.NoError(t, s.Delete(r.ID))
	_, err = s.Create(Input{Name: "approved name", Account: "*", Match: MatchExact, Pattern: "pwd", Action: ActionReview, DirectoryMatch: MatchExact, DirectoryPattern: "/srv/a", Priority: 10}, "admin")
	require.NoError(t, err)
	assert.NotEqual(t, review.PolicyKey, s.Decide(scope, "pwd", true, time.Now()).PolicyKey, "recreating a same-name rule must invalidate its approval")
	_, err = s.Create(Input{Name: "first explicit allow", Account: "*", Match: MatchExact, Pattern: "pwd", Action: ActionAllow, Priority: 1}, "admin")
	require.NoError(t, err)
	assert.True(t, s.Decide(Scope{Account: "ops"}, "pwd", true, time.Now()).Allowed, "existing priority semantics remain explicit")
	file := filepath.Join(t.TempDir(), "corrupt")
	require.NoError(t, os.WriteFile(file, []byte(`[{"id":"rule","name":"bad","account":"*","match":"exact","pattern":"pwd","action":"deny","directory_match":"regex","directory_pattern":"[","created_at":"2026-01-01T00:00:00Z"}]`), 0600))
	_, err = OpenStore(file)
	require.Error(t, err)
}
