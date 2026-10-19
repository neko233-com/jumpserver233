package sessionclient

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/monitorhistory"
)

type MonitorHistoryPage = monitorhistory.Page

func (c *Client) MonitorHistory(ctx context.Context, assetID string, from, to time.Time, stepSeconds int) (MonitorHistoryPage, error) {
	var page MonitorHistoryPage
	if !validMonitorID(assetID) || from.IsZero() || !to.After(from) || to.Sub(from) > monitorhistory.Retention || stepSeconds < 60 || stepSeconds > 3600 || stepSeconds%60 != 0 || (to.Sub(from)+time.Duration(stepSeconds)*time.Second-1)/(time.Duration(stepSeconds)*time.Second) > monitorhistory.MaxPoints {
		return page, errors.New("invalid monitoring history request")
	}
	q := url.Values{"from": {from.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}, "step": {strconv.Itoa(stepSeconds)}}
	e := c.jobRequest(ctx, "GET", "/api/v1/assets/"+url.PathEscape(assetID)+"/monitor-history?"+q.Encode(), nil, &page)
	return page, e
}
