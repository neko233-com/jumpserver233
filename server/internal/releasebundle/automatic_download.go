package releasebundle

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const downloadReceiptFile = ".jms233-download.json"

type downloadReceipt struct {
	Schema int    `json:"schema"`
	Owner  string `json:"owner"`
	RunID  string `json:"run_id"`
	SHA256 string `json:"sha256"`
}

func (s *stagingRoot) automaticDownloadName(run string) string {
	return ".jms233-maintenance/prepare-" + run
}
func newAutomaticDownload(ctx context.Context, path, run, sha string) (string, error) {
	if !validID(run) || !digest.MatchString(sha) {
		return "", ErrInvalid
	}
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return "", e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return "", e
	}
	if v.RunID != run || v.Policy.Mode == "off" {
		return "", context.Canceled
	}
	name := s.automaticDownloadName(run)
	if e = s.root.Mkdir(name, 0700); e != nil {
		return "", e
	}
	if e = writeStageJSON(s.root, name+"/"+downloadReceiptFile, downloadReceipt{1, s.owner.ID, run, sha}, true); e != nil {
		return "", e
	}
	return filepath.Join(s.path, filepath.FromSlash(name), "package.tar.gz"), nil
}
func (s *stagingRoot) removeAutomaticDownload(run string) error {
	if !validID(run) {
		return ErrInvalid
	}
	name := s.automaticDownloadName(run)
	info, e := s.root.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrStageConflict
	}
	var r downloadReceipt
	if e = readStageJSON(s.root, name+"/"+downloadReceiptFile, &r); e != nil || r.Schema != 1 || r.Owner != s.owner.ID || r.RunID != run || !digest.MatchString(r.SHA256) {
		return ErrStageConflict
	}
	target := filepath.Join(s.path, filepath.FromSlash(name))
	resolved, e := filepath.EvalSymlinks(target)
	if e != nil || !strings.EqualFold(target, resolved) || filepath.Dir(target) != filepath.Join(s.path, ".jms233-maintenance") {
		return ErrStageConflict
	}
	if e = fs.WalkDir(s.root.FS(), name, func(_ string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 || !d.IsDir() && !d.Type().IsRegular() {
			return ErrStageConflict
		}
		return nil
	}); e != nil {
		return e
	}
	return s.root.RemoveAll(name)
}
func cleanAutomaticDownload(ctx context.Context, path, run string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	return s.removeAutomaticDownload(run)
}

// Called only after acquiring the supervisor OS lock, never from the HTTP API.
func cleanAutomaticDownloads(ctx context.Context, path string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	rows, e := fs.ReadDir(s.root.FS(), ".jms233-maintenance")
	if e != nil {
		return e
	}
	for _, row := range rows {
		if !strings.HasPrefix(row.Name(), "prepare-") {
			continue
		}
		run := strings.TrimPrefix(row.Name(), "prepare-")
		if !validID(run) {
			return ErrStageConflict
		}
		if e = s.removeAutomaticDownload(run); e != nil {
			return e
		}
	}
	return nil
}
