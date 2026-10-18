package sessionclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Report = reporting.Report
type ReportQuery = reporting.Query
type ReportReceipt = reporting.Receipt
type ReportReceipts struct {
	Results []ReportReceipt `json:"results"`
	Total   int             `json:"total"`
}
type ReportDownload struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func reportParams(q ReportQuery) url.Values {
	v := url.Values{}
	if !q.From.IsZero() {
		v.Set("from", q.From.Format("2006-01-02T15:04:05.999999999Z07:00"))
	}
	if !q.To.IsZero() {
		v.Set("to", q.To.Format("2006-01-02T15:04:05.999999999Z07:00"))
	}
	v.Set("include_platform", strconv.FormatBool(q.IncludePlatform))
	if len(q.Sources) > 0 {
		v.Set("sources", strings.Join(q.Sources, ","))
	}
	return v
}
func (c *Client) ReportOverview(ctx context.Context, q ReportQuery) (Report, error) {
	var out Report
	e := c.jobRequest(ctx, "GET", "/api/v1/reports/overview?"+reportParams(q).Encode(), nil, &out)
	return out, e
}
func (c *Client) ReportExportHistory(ctx context.Context, all bool, offset, limit int) (ReportReceipts, error) {
	v := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}}
	if all {
		v.Set("scope", "all")
	}
	var out ReportReceipts
	e := c.jobRequest(ctx, "GET", "/api/v1/reports/exports?"+v.Encode(), nil, &out)
	return out, e
}
func (c *Client) ExportReport(ctx context.Context, q ReportQuery, partial bool, out io.Writer) (ReportDownload, error) {
	var result ReportDownload
	endpoint := *c.serverURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/reports/export.csv"
	v := reportParams(q)
	if partial {
		v.Set("allow_partial", "true")
	}
	endpoint.RawQuery = v.Encode()
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if e != nil {
		return result, e
	}
	if e = c.authorizeRequest(req); e != nil {
		return result, e
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return result, errors.New("report export unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, &APIError{StatusCode: resp.StatusCode, Detail: resp.Status}
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		return result, errors.New("invalid report export")
	}
	var buf bytes.Buffer
	if _, e = io.Copy(&buf, io.LimitReader(resp.Body, reporting.MaxCSVBytes+1)); e != nil {
		return result, e
	}
	if buf.Len() > reporting.MaxCSVBytes {
		return result, errors.New("report export exceeds limit")
	}
	sum := sha256.Sum256(buf.Bytes())
	result = ReportDownload{ID: resp.Header.Get("X-JMS-Report-ID"), SHA256: hex.EncodeToString(sum[:]), Bytes: buf.Len()}
	_, idError := hex.DecodeString(strings.TrimPrefix(result.ID, "report-export-"))
	if !strings.HasPrefix(result.ID, "report-export-") || len(result.ID) != 46 || idError != nil || result.SHA256 != resp.Header.Get("X-JMS-Report-SHA256") {
		return ReportDownload{}, errors.New("report digest or receipt mismatch")
	}
	var written int
	written, e = out.Write(buf.Bytes())
	if e == nil && written != buf.Len() {
		e = io.ErrShortWrite
	}
	return result, e
}
