package maintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prepareJournal(t *testing.T, opt Options) (string, string, restoreJournal) {
	t.Helper()
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	opt.DataDir = lock.DataDir
	require.NoError(t, lock.Close())
	id, e := randomID()
	require.NoError(t, e)
	stageName := "stage-" + id
	previousName := "previous-" + id
	stage := filepath.Join(controlDir(opt.DataDir), stageName)
	data := filepath.Join(stage, "data")
	previous := filepath.Join(controlDir(opt.DataDir), previousName)
	require.NoError(t, os.MkdirAll(data, 0700))
	root, e := os.OpenRoot(data)
	require.NoError(t, e)
	m, hash, e := readArchive(context.Background(), opt, root)
	root.Close()
	require.NoError(t, e)
	body, e := json.Marshal(stagedState{Manifest: m, ManifestSHA: hash})
	require.NoError(t, e)
	require.NoError(t, atomicPrivate(filepath.Join(stage, "manifest.json"), body))
	sum := sha256.Sum256(body)
	raw, _ := json.Marshal(receipt{BackupID: m.Result.BackupID, ManifestSHA: hash, AppliedAt: time.Now().UTC()})
	require.NoError(t, atomicPrivate(filepath.Join(data, receiptName), raw))
	old, e := topEntries(opt.DataDir)
	require.NoError(t, e)
	next, e := topEntries(data)
	require.NoError(t, e)
	j := restoreJournal{Format: 1, Phase: "saving-old", Stage: stageName, Previous: previousName, Old: old, New: next, StageSHA: hex.EncodeToString(sum[:]), ManifestSHA: hash, Result: m.Result}
	j.Result.PreviousDataDir = previous
	require.NoError(t, writeJournal(opt.DataDir, j))
	return stage, previous, j
}
func saveOld(t *testing.T, dataDir, previous string, j restoreJournal) {
	t.Helper()
	require.NoError(t, os.MkdirAll(previous, 0700))
	for _, name := range j.Old {
		require.NoError(t, os.Rename(filepath.Join(dataDir, name), filepath.Join(previous, name)))
	}
}
func TestBackupInterruptedDirectorySwitchRecoversIdempotently(t *testing.T) {
	for _, point := range []string{"prepared", "old-partial", "old-moved", "new-partial", "new-moved", "stage-lost", "stage-corrupt", "foreign-journal"} {
		t.Run(point, func(t *testing.T) {
			opt := fixture(t)
			_, e := Create(context.Background(), opt)
			require.NoError(t, e)
			opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "target")
			require.NoError(t, os.Mkdir(opt.DataDir, 0700))
			for _, name := range []string{"old", "other"} {
				require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, name), []byte("old-data"), 0600))
			}
			stage, previous, j := prepareJournal(t, opt)
			switch point {
			case "old-partial":
				require.NoError(t, os.Mkdir(previous, 0700))
				name := j.Old[0]
				require.NoError(t, os.Rename(filepath.Join(opt.DataDir, name), filepath.Join(previous, name)))
			case "old-moved", "new-partial", "new-moved", "stage-lost":
				saveOld(t, opt.DataDir, previous, j)
				if point == "new-partial" || point == "new-moved" {
					j.Phase = "installing-new"
					require.NoError(t, writeJournal(opt.DataDir, j))
					for i, name := range j.New {
						if point == "new-partial" && i > 0 {
							break
						}
						require.NoError(t, os.Rename(filepath.Join(stage, "data", name), filepath.Join(opt.DataDir, name)))
					}
				}
				if point == "stage-lost" {
					require.NoError(t, os.RemoveAll(stage))
				}
			case "stage-corrupt":
				require.NoError(t, os.WriteFile(filepath.Join(stage, "data", "vault.key"), bytes.Repeat([]byte{4}, 32), 0600))
			case "foreign-journal":
				j.Stage = "../outside"
				raw, _ := json.Marshal(j)
				require.NoError(t, atomicPrivate(journalPath(opt.DataDir), raw))
			}
			lock, e := Acquire(opt.DataDir)
			require.NoError(t, e)
			defer lock.Close()
			e = Recover(context.Background(), lock.DataDir)
			if point == "stage-corrupt" || point == "foreign-journal" {
				assert.Error(t, e)
				assert.FileExists(t, filepath.Join(opt.DataDir, "old"))
				return
			}
			require.NoError(t, e)
			require.NoError(t, Recover(context.Background(), lock.DataDir))
			assert.NoFileExists(t, journalPath(opt.DataDir))
			if point == "stage-lost" {
				assert.FileExists(t, filepath.Join(opt.DataDir, "old"))
			} else {
				assert.FileExists(t, filepath.Join(opt.DataDir, "vault.key"))
				assert.FileExists(t, filepath.Join(previous, "old"))
				assert.NoDirExists(t, stage)
			}
		})
	}
}
func TestBackupExplicitRollbackResumesAfterItsOwnInterruptedMoves(t *testing.T) {
	for _, point := range []string{"installed-part", "quarantined-part", "restored-old-part"} {
		t.Run(point, func(t *testing.T) {
			opt := fixture(t)
			_, e := Create(context.Background(), opt)
			require.NoError(t, e)
			opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "target")
			require.NoError(t, os.Mkdir(opt.DataDir, 0700))
			for _, name := range []string{"old", "other"} {
				require.NoError(t, os.WriteFile(filepath.Join(opt.DataDir, name), []byte("original-data"), 0600))
			}
			stage, previous, j := prepareJournal(t, opt)
			saveOld(t, opt.DataDir, previous, j)
			j.Phase = "installing-new"
			require.NoError(t, writeJournal(opt.DataDir, j))
			name := j.New[0]
			require.NoError(t, os.Rename(filepath.Join(stage, "data", name), filepath.Join(opt.DataDir, name)))
			if point != "installed-part" {
				j.Phase = "rollback-new"
				require.NoError(t, writeJournal(opt.DataDir, j))
				q := filepath.Join(stage, "failed-data")
				require.NoError(t, os.MkdirAll(q, 0700))
				require.NoError(t, os.Rename(filepath.Join(opt.DataDir, name), filepath.Join(q, name)))
			}
			if point == "restored-old-part" {
				j.Phase = "rollback-old"
				require.NoError(t, writeJournal(opt.DataDir, j))
				name := j.Old[0]
				require.NoError(t, os.Rename(filepath.Join(previous, name), filepath.Join(opt.DataDir, name)))
			}
			lock, e := Acquire(opt.DataDir)
			require.NoError(t, e)
			defer lock.Close()
			require.NoError(t, Rollback(context.Background(), lock.DataDir))
			require.NoError(t, Rollback(context.Background(), lock.DataDir))
			require.NoError(t, Recover(context.Background(), lock.DataDir))
			assert.NoFileExists(t, journalPath(opt.DataDir))
			for _, name := range []string{"old", "other"} {
				body, e := os.ReadFile(filepath.Join(opt.DataDir, name))
				require.NoError(t, e)
				assert.Equal(t, "original-data", string(body))
			}
		})
	}
}
