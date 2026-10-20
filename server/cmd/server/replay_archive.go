package main

import (
	"context"
	"crypto/subtle"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/api"
	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

func openReplayArchive(d *api.Dependencies, directory string, key []byte, docs *storage.Documents) error {
	source, e := replayarchive.NewRecordings(directory, key)
	if e != nil {
		return e
	}
	d.ReplayArchive, e = replayarchive.Open(filepath.Join(directory, "replay-archive.json"), key, docs, source, replayBackendFactory(docs, d.Assets))
	if e != nil {
		return e
	}
	d.ReplayArchiveDatabase = docs != nil
	if d.Sessions != nil {
		d.Sessions.SetReplayArchive(d.ReplayArchive)
	}
	if d.Desktops != nil {
		d.Desktops.SetReplayArchive(d.ReplayArchive)
	}
	return nil
}

// Compose inventory connectors here so importing archive/SDK types does not
// initialize server-only asset protocol drivers in the native CLI.
func replayBackendFactory(docs *storage.Documents, inventory *assets.Service) replayarchive.Factory {
	return func(ctx context.Context, c replayarchive.Config) (replaystore.Objects, error) {
		switch c.Provider {
		case "s3", "oss", "cos", "obs":
			if c.Cloud == nil || c.Cloud.Provider != c.Provider {
				return nil, replayarchive.ErrInvalid
			}
			return replaystore.NewCloud(*c.Cloud)
		case "postgres":
			return replaystore.NewDatabase(docs)
		case "sftp":
			if inventory == nil {
				return nil, replayarchive.ErrUnavailable
			}
			target, binding, e := inventory.ReplayStorageTarget(c.SFTPAssetID)
			if e != nil || subtle.ConstantTimeCompare([]byte(target), []byte(c.SFTPTarget)) != 1 {
				return nil, replayarchive.ErrUnavailable
			}
			_, remote, e := inventory.OpenSFTP(assets.WithConnectionBinding(ctx, binding), c.SFTPAssetID)
			if e != nil {
				return nil, replayarchive.ErrUnavailable
			}
			current, _, e := inventory.ReplayStorageTarget(c.SFTPAssetID)
			if e != nil || subtle.ConstantTimeCompare([]byte(current), []byte(c.SFTPTarget)) != 1 {
				remote.Close()
				return nil, replayarchive.ErrUnavailable
			}
			objects, e := replaystore.NewSFTP(remote, c.SFTPDirectory)
			if e != nil {
				remote.Close()
				return nil, replayarchive.ErrUnavailable
			}
			return objects, nil
		default:
			return nil, replayarchive.ErrUnavailable
		}
	}
}
