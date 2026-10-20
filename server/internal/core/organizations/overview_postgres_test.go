package organizations

import (
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOrganizationOverviewPostgresReopenKeepsExclusionsAndArchiveMetadata(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL fixture")
	}
	docs, err := storage.OpenPostgres(t.Context(), dsn, fmt.Sprintf("overview-%d", time.Now().UnixNano()))
	require.NoError(t, err)
	defer docs.Close()
	defer docs.Delete("organizations")
	s, err := Open(filepath.Join(t.TempDir(), "organizations.json"), docs)
	require.NoError(t, err)
	o, err := s.Save("", Input{Name: "Shared overview", Enabled: true}, "admin")
	require.NoError(t, err)
	_, err = s.SaveMember(o.ID, MemberInput{UserID: "operator", Role: "member"}, "admin")
	require.NoError(t, err)
	_, err = s.SaveMember(DefaultID, MemberInput{UserID: "operator", Role: "none"}, "admin")
	require.NoError(t, err)
	require.NoError(t, s.Archive(o.ID, o.Revision, false, "admin"))
	before := s.OverviewMetadata(true, []string{"operator", "admin"})
	reopened, err := Open(filepath.Join(t.TempDir(), "organizations.json"), docs)
	require.NoError(t, err)
	assert.Equal(t, before, reopened.OverviewMetadata(true, []string{"operator", "admin"}))
	assert.Equal(t, 1, before[0].Members)
	assert.True(t, before[1].Archived)
}
