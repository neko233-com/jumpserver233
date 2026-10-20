package sessionclient

import (
	"context"
	"fmt"
	"regexp"

	"github.com/neko233-com/jumpserver233/server/internal/core/announcements"
)

type AnnouncementInput = announcements.Input
type Announcement = announcements.Notice
type AnnouncementReading = announcements.Reading
type AnnouncementAudit = announcements.Audit
type AnnouncementPage struct {
	Results []announcements.View `json:"results"`
	Total   int                  `json:"total"`
	Unread  int                  `json:"unread"`
}
type AnnouncementAuditPage struct {
	Results []AnnouncementAudit `json:"results"`
	Total   int                 `json:"total"`
}

var validAnnouncementID = regexp.MustCompile(`^notice-[a-f0-9]{32}$`)

func (c *Client) Announcements(ctx context.Context, manage bool, offset, limit int) (AnnouncementPage, error) {
	var out AnnouncementPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, announcements.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/announcements?manage=%t&offset=%d&limit=%d", manage, offset, limit), nil, &out)
	return out, e
}
func (c *Client) SaveAnnouncement(ctx context.Context, id string, in AnnouncementInput) (Announcement, error) {
	var out Announcement
	if id != "" && !validAnnouncementID.MatchString(id) {
		return out, announcements.ErrInvalid
	}
	normalized, e := announcements.Prepare(in)
	if e != nil {
		return out, e
	}
	method, path := "POST", "/api/v1/announcements"
	if id != "" {
		method, path = "PUT", path+"/"+id
	}
	e = c.jobRequest(ctx, method, path, normalized, &out)
	return out, e
}
func (c *Client) DeleteAnnouncement(ctx context.Context, id string, revision int, requestID string) error {
	if !validAnnouncementID.MatchString(id) || revision < 1 {
		return announcements.ErrInvalid
	}
	return c.jobRequest(ctx, "DELETE", "/api/v1/announcements/"+id, struct {
		Revision  int    `json:"revision"`
		RequestID string `json:"request_id"`
	}{revision, requestID}, nil)
}
func (c *Client) ReadAnnouncement(ctx context.Context, id string, revision int) (AnnouncementReading, error) {
	var out AnnouncementReading
	if !validAnnouncementID.MatchString(id) || revision < 1 {
		return out, announcements.ErrInvalid
	}
	e := c.jobRequest(ctx, "POST", "/api/v1/announcements/"+id+"/read", struct {
		Revision int `json:"revision"`
	}{revision}, &out)
	return out, e
}
func (c *Client) AnnouncementAudit(ctx context.Context, offset, limit int) (AnnouncementAuditPage, error) {
	var out AnnouncementAuditPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, announcements.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/announcements/audit?offset=%d&limit=%d", offset, limit), nil, &out)
	return out, e
}
