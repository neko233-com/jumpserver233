package api

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"net/url"
)

func platformLoginNotificationAllowed(ctx context.Context, d Dependencies, userID string, source notifications.Source) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	r, e := d.LoginAudit.Get(source.ID)
	if errors.Is(e, loginaudit.ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if r.Notification == "" || r.Notification != source.Action {
		return false, nil
	}
	u, p, ok := globalLoginActor(d, userID)
	if !ok {
		return false, nil
	}
	if r.Notification == "platform_review_pending" {
		if d.LoginReviews == nil {
			return false, nil
		}
		review, e := d.LoginReviews.Get(r.ReviewID)
		if errors.Is(e, loginreviews.ErrNotFound) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if review.State != loginreviews.Pending {
			return false, nil
		}
	}
	return canReadLoginAudit(d, u, p, r), nil
}
func platformLoginNotificationFeeds(d Dependencies) []notifications.Feed {
	if d.LoginAudit == nil {
		return nil
	}
	return []notifications.Feed{{Name: "platform-logins", Read: d.LoginAudit.NotificationFeed,
		Link: func(e eventfeed.Event) string { return "/console/login-audit?event=" + url.QueryEscape(e.ResourceID) },
		Recipients: func(ctx context.Context, event eventfeed.Event) ([]notifications.Recipient, error) {
			r, e := d.LoginAudit.Get(event.ResourceID)
			if errors.Is(e, loginaudit.ErrNotFound) {
				return []notifications.Recipient{}, nil
			}
			if e != nil {
				return nil, e
			}
			out := []notifications.Recipient{}
			for _, u := range d.Auth.ActiveUsersSnapshot() {
				p := globalLoginPermissions(d, u)
				if u.ID == r.UserID || p.Allows("audit.logins.view_all") {
					out = append(out, notifications.Recipient{UserID: u.ID, Topic: "security"})
				}
				if r.Notification == "platform_review_pending" && canReviewPlatformLogin(d, u, p, r.ReviewID) {
					out = append(out, notifications.Recipient{UserID: u.ID, Topic: "approvals"})
				}
			}
			return out, ctx.Err()
		}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
			return platformLoginNotificationAllowed(ctx, d, id, source)
		},
	}}
}
