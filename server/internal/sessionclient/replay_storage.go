package sessionclient

import (
	"context"
	"fmt"
	"regexp"
	"slices"

	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
)

type ReplayStorageConfig = replayarchive.Config
type ReplayStorageInput = replayarchive.Input
type ReplayStorageRef = replayarchive.Ref
type ReplayStorageRecord = replayarchive.Record
type ReplayStorageSettings struct {
	Config            ReplayStorageConfig `json:"config"`
	PostgresAvailable bool                `json:"postgres_available"`
}
type ReplayStoragePage struct {
	Results []ReplayStorageRecord `json:"results"`
	Total   int                   `json:"total"`
}
type ReplayStorageAuditPage struct {
	Results []replayarchive.Audit `json:"results"`
	Total   int                   `json:"total"`
}

const replayStorageBase = "/api/v1/settings/replay-storage"

var replayStorageRequest = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)

func redactReplayStorage(c *ReplayStorageConfig) {
	if c.Cloud != nil {
		c.HasSecret = c.HasSecret || c.Cloud.SecretAccessKey != ""
		c.HasSessionToken = c.HasSessionToken || c.Cloud.SessionToken != ""
		c.Cloud.SecretAccessKey = ""
		c.Cloud.SessionToken = ""
	}
}
func (c *Client) ReplayStorage(ctx context.Context) (ReplayStorageSettings, error) {
	var out ReplayStorageSettings
	e := c.jobRequest(ctx, "GET", replayStorageBase, nil, &out)
	redactReplayStorage(&out.Config)
	return out, e
}
func (c *Client) SaveReplayStorage(ctx context.Context, in ReplayStorageInput) (ReplayStorageConfig, error) {
	var out ReplayStorageConfig
	if in.Revision < 0 || !replayStorageRequest.MatchString(in.RequestID) || !slices.Contains([]string{"local", "s3", "oss", "cos", "obs", "sftp", "postgres"}, in.Provider) {
		return out, replayarchive.ErrInvalid
	}
	e := c.jobRequest(ctx, "PUT", replayStorageBase, in, &out)
	redactReplayStorage(&out)
	return out, e
}
func (c *Client) ReplayStorageRecords(ctx context.Context, offset, limit int) (ReplayStoragePage, error) {
	var out ReplayStoragePage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, replayarchive.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("%s/records?offset=%d&limit=%d", replayStorageBase, offset, limit), nil, &out)
	return out, e
}
func (c *Client) ReplayStorageAudit(ctx context.Context, offset, limit int) (ReplayStorageAuditPage, error) {
	var out ReplayStorageAuditPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, replayarchive.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("%s/audit?offset=%d&limit=%d", replayStorageBase, offset, limit), nil, &out)
	return out, e
}
func (c *Client) ReplayStorageRecord(ctx context.Context, ref ReplayStorageRef) (ReplayStorageRecord, error) {
	var out ReplayStorageRecord
	if !replayarchive.ValidRef(ref) {
		return out, replayarchive.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", replayStorageBase+"/records/"+ref.Kind+"/"+ref.SessionID, nil, &out)
	return out, e
}
func (c *Client) ReplayStorageAction(ctx context.Context, ref ReplayStorageRef, action, request string) (ReplayStorageRecord, error) {
	var out ReplayStorageRecord
	if !replayarchive.ValidRef(ref) || !slices.Contains([]string{"archive", "retry", "verify", "evict"}, action) || !replayStorageRequest.MatchString(request) {
		return out, replayarchive.ErrInvalid
	}
	e := c.jobRequest(ctx, "POST", replayStorageBase+"/records/"+ref.Kind+"/"+ref.SessionID+"/"+action, map[string]string{"request_id": request}, &out)
	return out, e
}
