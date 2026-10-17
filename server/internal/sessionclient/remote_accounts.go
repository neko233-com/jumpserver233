package sessionclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type RemoteAccountState struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	UID         uint32 `json:"uid,omitempty"`
	ProvisionID string `json:"provision_id,omitempty"`
}
type RemoteAccountTask struct {
	Operation struct {
		Task struct {
			ID       string `json:"id"`
			Action   string `json:"action"`
			Username string `json:"username"`
			UID      uint32 `json:"uid"`
		} `json:"task"`
		Mode      string `json:"mode"`
		Attempt   uint64 `json:"attempt"`
		AccountID string `json:"account_id"`
	} `json:"operation"`
	Revision  int    `json:"revision"`
	State     string `json:"state"`
	JobID     string `json:"job_id,omitempty"`
	ReviewID  string `json:"review_id,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Result    *struct {
		State     string `json:"state"`
		Stage     string `json:"stage"`
		ErrorCode string `json:"error_code,omitempty"`
		UID       uint32 `json:"uid"`
		Home      string `json:"home,omitempty"`
	} `json:"result,omitempty"`
}
type RemoteAccountInput struct {
	Action    string `json:"action"`
	Username  string `json:"username"`
	Shell     string `json:"shell,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
}
type RemoteAccountTaskPage struct {
	Results []RemoteAccountTask `json:"results"`
	Total   int                 `json:"total"`
}

func remoteAccountPath(asset string) string {
	return "/api/v1/assets/" + url.PathEscape(asset) + "/remote-account-tasks"
}
func (c *Client) RemoteAccountTasks(ctx context.Context, asset string, offset, limit int) (RemoteAccountTaskPage, error) {
	var out RemoteAccountTaskPage
	e := c.jobRequest(ctx, http.MethodGet, remoteAccountPath(asset)+"?offset="+strconv.Itoa(offset)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out, e
}
func (c *Client) CreateRemoteAccountTask(ctx context.Context, asset string, in RemoteAccountInput) (RemoteAccountTask, error) {
	var out RemoteAccountTask
	e := c.jobRequest(ctx, http.MethodPost, remoteAccountPath(asset), in, &out)
	return out, e
}
func (c *Client) SubmitRemoteAccountTask(ctx context.Context, asset, id string) (RemoteAccountTask, error) {
	var out RemoteAccountTask
	e := c.jobRequest(ctx, http.MethodPost, remoteAccountPath(asset)+"/"+url.PathEscape(id)+"/submit", nil, &out)
	return out, e
}
func (c *Client) AttemptRemoteAccountTask(ctx context.Context, asset, id, mode string, revision int) (RemoteAccountTask, error) {
	var out RemoteAccountTask
	e := c.jobRequest(ctx, http.MethodPost, remoteAccountPath(asset)+"/"+url.PathEscape(id)+"/attempts", struct {
		Revision int    `json:"revision"`
		Mode     string `json:"mode"`
	}{revision, mode}, &out)
	return out, e
}
