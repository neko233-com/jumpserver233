package sessionclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type AccountCollectionPlan struct {
	LastRun *struct {
		State string `json:"state"`
		Items []struct {
			State    string `json:"state"`
			JobID    string `json:"job_id,omitempty"`
			ReviewID string `json:"review_id,omitempty"`
		} `json:"items"`
	} `json:"last_run,omitempty"`
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Owner     string    `json:"owner"`
	Name      string    `json:"name"`
	AssetIDs  []string  `json:"asset_ids"`
	Account   string    `json:"collection_account"`
	Enabled   bool      `json:"enabled"`
	Interval  int       `json:"interval_seconds"`
	Revision  int       `json:"config_revision"`
	NextRun   time.Time `json:"next_run,omitzero"`
	LastRunID string    `json:"last_run_id,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}
type AccountCollectionPlanInput struct {
	Name      string `json:"name,omitempty"`
	Interval  int    `json:"interval_seconds,omitempty"`
	RequestID string `json:"request_id"`
}
type AccountCollectionPlanUpdate struct {
	Enabled  bool `json:"enabled"`
	Interval int  `json:"interval_seconds,omitempty"`
	Revision int  `json:"revision"`
}
type AccountCollectionReceiptPage struct {
	Results    []AccountCollectionReceipt `json:"results"`
	NextBefore uint64                     `json:"next_before"`
}
type AccountCollectionReceipt struct {
	Index      uint64    `json:"index"`
	ObservedAt time.Time `json:"observed_at"`
	Source     struct {
		AssetID   string `json:"asset_id"`
		AssetName string `json:"asset_name"`
		Account   string `json:"account"`
	} `json:"source"`
	Collector struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"collector"`
	Receipt struct {
		PlanID   string `json:"plan_id"`
		Sequence uint64 `json:"sequence"`
		RunID    string `json:"run_id"`
		JobID    string `json:"job_id,omitempty"`
		State    string `json:"state"`
		Job      *struct {
			State     string `json:"state"`
			ErrorCode string `json:"error_code,omitempty"`
			Stdout    string `json:"stdout,omitempty"`
		} `json:"job,omitempty"`
	} `json:"receipt"`
}

func collectionPath(asset string) string {
	return "/api/v1/assets/" + url.PathEscape(asset) + "/account-discovery"
}
func (c *Client) AccountCollectionPlans(ctx context.Context, asset string) ([]AccountCollectionPlan, error) {
	out := []AccountCollectionPlan{}
	e := c.jobRequest(ctx, http.MethodGet, collectionPath(asset)+"/plans", nil, &out)
	return out, e
}
func (c *Client) CreateAccountCollectionPlan(ctx context.Context, asset string, in AccountCollectionPlanInput) (AccountCollectionPlan, error) {
	var out AccountCollectionPlan
	e := c.jobRequest(ctx, http.MethodPost, collectionPath(asset)+"/plans", in, &out)
	return out, e
}
func (c *Client) UpdateAccountCollectionPlan(ctx context.Context, asset, plan string, in AccountCollectionPlanUpdate) (AccountCollectionPlan, error) {
	var out AccountCollectionPlan
	e := c.jobRequest(ctx, http.MethodPut, collectionPath(asset)+"/plans/"+url.PathEscape(plan), in, &out)
	return out, e
}
func (c *Client) AccountCollectionHistory(ctx context.Context, asset string, before uint64, limit int) (AccountCollectionReceiptPage, error) {
	var out AccountCollectionReceiptPage
	e := c.jobRequest(ctx, http.MethodGet, collectionPath(asset)+"/collections?before="+strconv.FormatUint(before, 10)+"&limit="+strconv.Itoa(limit), nil, &out)
	return out, e
}
