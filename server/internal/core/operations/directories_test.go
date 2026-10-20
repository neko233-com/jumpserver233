package operations

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperationDirectorySnapshotsReachEveryScheduleAndSurviveRestart(t *testing.T) {
	for _, kind := range []string{"batch", "once", "interval", "cron"} {
		t.Run(kind, func(t *testing.T) {
			s, js, now := setup(t, nil)
			in := PlanInput{Name: "directory " + kind, AssetIDs: []string{"a"}, Command: "pwd", WorkingDirectory: "/srv/work/deploy", Kind: kind, RequestID: "directory-" + kind}
			switch kind {
			case "once":
				in.RunAt = now.Add(time.Minute)
			case "interval":
				in.IntervalSeconds = 60
			case "cron":
				in.CronExpression, in.Timezone = "* * * * *", "UTC"
			}
			p := plan(t, s, in)
			captured := make(chan jobs.Input, 1)
			s.submit = func(_ string, input jobs.Input, _ string) (Submission, error) {
				captured <- input
				return Submission{}, ErrDenied
			}
			*now = p.NextRun
			s.Tick()
			select {
			case input := <-captured:
				assert.Equal(t, in.WorkingDirectory, input.WorkingDirectory)
				assert.Equal(t, "pwd", input.Command)
			case <-time.After(time.Second):
				t.Fatal("directory snapshot was not dispatched")
			}
			r := lastRun(t, s, p)
			assert.Equal(t, in.WorkingDirectory, r.WorkingDirectory)
			assert.Equal(t, in.WorkingDirectory, jobInput(r, "a").WorkingDirectory)
			s.Close()
			peer, err := Open(s.path, make([]byte, 32), nil, js)
			require.NoError(t, err)
			defer peer.Close()
			loaded, err := peer.Run(r.ID)
			require.NoError(t, err)
			assert.Equal(t, in.WorkingDirectory, loaded.WorkingDirectory)
			assert.Equal(t, in.WorkingDirectory, peer.Plans("owner")[0].WorkingDirectory)
		})
	}
}

func TestOperationTemplateDirectoryIsImmutableInCreateReplayAndScheduleEdits(t *testing.T) {
	s, _, now := setup(t, nil)
	tpl, err := s.SaveTemplate("", "owner", "owner", TemplateInput{Name: "private", Command: "pwd", WorkingDirectory: "/srv/work/one"})
	require.NoError(t, err)
	in := PlanInput{Name: "frozen", AssetIDs: []string{"a"}, TemplateID: tpl.ID, Kind: "interval", IntervalSeconds: 60, RequestID: "frozen-directory"}
	prepared, revision, err := s.Prepare("owner", in)
	require.NoError(t, err)
	assert.Equal(t, tpl.WorkingDirectory, prepared.WorkingDirectory)
	forgedTemplate := in
	forgedTemplate.WorkingDirectory = "/srv/work/two"
	_, _, err = s.Prepare("owner", forgedTemplate)
	assert.ErrorIs(t, err, ErrInvalid)
	changed := tpl.TemplateInput
	changed.WorkingDirectory = "/srv/work/two"
	updated, err := s.SaveTemplate(tpl.ID, "owner", "owner", changed)
	require.NoError(t, err)
	p, err := s.CreatePlan("owner", "owner", prepared, revision)
	require.NoError(t, err)
	assert.Equal(t, "/srv/work/one", p.WorkingDirectory)
	require.NoError(t, s.DeleteTemplate(tpl.ID, "owner", updated.Revision))
	for n := 0; n < 2; n++ {
		replay, found, err := s.ReplayPlan("owner", in)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, p.ID, replay.ID)
		assert.Equal(t, p.WorkingDirectory, replay.WorkingDirectory)
	}
	forged := in
	forged.WorkingDirectory = "/srv/work/two"
	_, found, err := s.ReplayPlan("owner", forged)
	assert.True(t, found)
	assert.ErrorIs(t, err, ErrConflict)
	_, _, err = s.Prepare("owner", PlanInput{Name: "override", AssetIDs: []string{"a"}, TemplateID: tpl.ID, WorkingDirectory: "/srv/work/two", Kind: "batch", RequestID: "override"})
	assert.ErrorIs(t, err, ErrNotFound)
	updatedPlan, err := s.UpdateSchedule(p.ID, ScheduleUpdate{Revision: p.ConfigRevision, Schedule: Schedule{Kind: "interval", IntervalSeconds: 120}}, ScheduleActor{ID: "owner", Name: "owner"})
	require.NoError(t, err)
	assert.Equal(t, p.WorkingDirectory, updatedPlan.WorkingDirectory)
	_, err = s.UpdateSchedule(p.ID, ScheduleUpdate{Revision: p.ConfigRevision, Schedule: Schedule{Kind: "interval", IntervalSeconds: 180}}, ScheduleActor{ID: "owner", Name: "owner"})
	assert.ErrorIs(t, err, ErrConflict)
	assert.True(t, updatedPlan.NextRun.After(*now))
}

func writeDirectoryEnvelope(t *testing.T, s *Service, st state, version int) []byte {
	t.Helper()
	plain, err := json.Marshal(st)
	require.NoError(t, err)
	nonce := make([]byte, s.aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	raw, err := json.Marshal(envelope{Version: version, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte(fmt.Sprintf("jms233/operations/v%d", version)))})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(s.path, raw, 0600))
	return raw
}

func TestOperationDirectoryEncryptedVersionGateAndLegacyMigration(t *testing.T) {
	for version := 1; version <= 4; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s, js, _ := setup(t, nil)
			tpl, err := s.SaveTemplate("", "owner", "owner", TemplateInput{Name: "legacy", Command: "private-command"})
			require.NoError(t, err)
			legacy := clone(s.data)
			s.Close()
			writeDirectoryEnvelope(t, s, legacy, version)
			peer, err := Open(s.path, make([]byte, 32), nil, js)
			require.NoError(t, err)
			assert.Equal(t, tpl, peer.Templates("owner")[0])
			tpl.WorkingDirectory = "/srv/work/deploy"
			_, err = peer.SaveTemplate(tpl.ID, "owner", "owner", tpl.TemplateInput)
			require.NoError(t, err)
			peer.Close()
			raw, err := os.ReadFile(s.path)
			require.NoError(t, err)
			assert.Contains(t, string(raw), `"version":6`)
			assert.NotContains(t, string(raw), tpl.WorkingDirectory)
			assert.NotContains(t, string(raw), tpl.Command)
			current, err := Open(s.path, make([]byte, 32), nil, js)
			require.NoError(t, err)
			assert.Equal(t, tpl.WorkingDirectory, current.Templates("owner")[0].WorkingDirectory)
			current.Close()
			forged := clone(legacy)
			stored := forged.Templates[tpl.ID]
			stored.WorkingDirectory = tpl.WorkingDirectory
			forged.Templates[tpl.ID] = stored
			before := writeDirectoryEnvelope(t, s, forged, version)
			_, err = Open(s.path, make([]byte, 32), nil, js)
			assert.ErrorIs(t, err, ErrInvalid)
			after, err := os.ReadFile(s.path)
			require.NoError(t, err)
			assert.Equal(t, before, after, "rejected format must preserve original bytes")
		})
	}
}

func TestOperationDirectoryValidationAndManagementIsolation(t *testing.T) {
	s, _, _ := setup(t, nil)
	for _, directory := range []string{"relative", "/", "/srv/work/../escape", "/srv/work\nother", "/etc/ssh"} {
		_, err := s.SaveTemplate("", "owner", "owner", TemplateInput{Name: "invalid", Command: "pwd", WorkingDirectory: directory})
		assert.ErrorIs(t, err, ErrInvalid)
		_, _, err = s.Prepare("owner", PlanInput{Name: "invalid", Command: "pwd", AssetIDs: []string{"a"}, Kind: "batch", RequestID: "invalid", WorkingDirectory: directory})
		assert.ErrorIs(t, err, ErrInvalid)
	}
	_, err := s.createPlan("owner", "owner", PlanInput{WorkingDirectory: "/srv/work"}, 0, &hostplugins.Operation{}, nil, "", "", "")
	assert.ErrorIs(t, err, ErrInvalid)
	st := clone(s.data)
	st.Plans["invalid"] = Plan{PlanInput: PlanInput{WorkingDirectory: "/srv/work"}, HostPlugin: &hostplugins.Operation{}}
	assert.ErrorIs(t, validateOperationDirectories(st, 5), ErrInvalid)
	assert.Empty(t, s.Plans("owner"))
}

func TestPlaybookStepDirectoryIsPartOfExecutionAuthority(t *testing.T) {
	s, _, now := nativeSetup(t, nil)
	meta := playbooks.Execution{RunID: "run-" + strings.Repeat("a", 32), StepID: "step-" + strings.Repeat("b", 32), ProgramID: strings.Repeat("c", 64)}
	sum := sha256.Sum256([]byte("pwd"))
	step := StepResult{ID: meta.StepID, Command: "pwd", CommandSHA256: hex.EncodeToString(sum[:]), TimeoutSeconds: 10}
	r := Run{ID: meta.RunID, OwnerID: "owner", ProgramID: meta.ProgramID, WorkingDirectory: "/srv/work/deploy", State: "running", Deadline: now.Add(time.Hour), Items: []Item{{AssetID: "a", State: "running", Steps: []StepResult{step}}}}
	s.data.Runs[r.ID] = r
	in := stepInput(r, "a", step)
	assert.Equal(t, r.WorkingDirectory, in.WorkingDirectory)
	assert.True(t, s.WorkflowJobAllowed("owner", "a", meta, in.Command, in.WorkingDirectory))
	for _, forged := range []string{"", "/srv/work", "/srv/work/sibling"} {
		assert.False(t, s.WorkflowJobAllowed("owner", "a", meta, in.Command, forged))
	}
	assert.False(t, s.WorkflowJobAllowed("foreign", "a", meta, in.Command, in.WorkingDirectory))
	assert.False(t, s.WorkflowJobAllowed("owner", "other", meta, in.Command, in.WorkingDirectory))
	assert.False(t, s.WorkflowJobAllowed("owner", "a", meta, "forged", in.WorkingDirectory))
}
