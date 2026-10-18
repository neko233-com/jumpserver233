package api

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"net/url"
)

func notificationActor(ctx context.Context, d Dependencies, id string) (coreauth.User, rbac.Snapshot, bool) {
	if ctx.Err() != nil {
		return coreauth.User{}, rbac.Snapshot{}, false
	}
	u, ok := jobOwner(d, id)
	if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
		return u, rbac.Snapshot{}, false
	}
	return u, effectivePermissions(u, d.RBAC, d.Groups), true
}
func notificationAudience(ctx context.Context, d Dependencies, selectTopics func(coreauth.User, rbac.Snapshot) []string) ([]notifications.Recipient, error) {
	out := []notifications.Recipient{}
	for _, user := range d.Auth.ListUsers() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		u, p, ok := notificationActor(ctx, d, user.ID)
		if !ok {
			continue
		}
		for _, topic := range selectTopics(u, p) {
			out = append(out, notifications.Recipient{UserID: u.ID, Topic: topic})
		}
	}
	return out, nil
}
func securityNotificationFeeds(d Dependencies) []notifications.Feed {
	out := []notifications.Feed{}
	link := func(kind string) func(eventfeed.Event) string {
		return func(e eventfeed.Event) string {
			return "/console/notification-sources/" + kind + "/" + url.PathEscape(e.ResourceID)
		}
	}
	if d.AccessReviews != nil {
		out = append(out, notifications.Feed{Name: "access-reviews", Read: d.AccessReviews.NotificationFeed, Link: link("access-reviews"),
			Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(u coreauth.User, p rbac.Snapshot) []string {
					topics := []string{}
					if e.State == "asset_review_pending" {
						if u.ID == e.OwnerID {
							topics = append(topics, "security")
						}
						if p.Allows("reviews.login.manage") {
							topics = append(topics, "approvals")
						}
					} else if u.ID == e.OwnerID || p.Allows("reviews.login.manage") {
						topics = append(topics, "security")
					}
					return topics
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				_, p, ok := notificationActor(ctx, d, id)
				if !ok {
					return false, ctx.Err()
				}
				r, e := d.AccessReviews.NotificationInfo(source.ID)
				if errors.Is(e, accessreviews.ErrNotFound) {
					return false, nil
				}
				if e != nil {
					return false, e
				}
				if source.Action == "review" {
					return p.Allows("reviews.login.manage") && r.State == accessreviews.StatePending, nil
				}
				if source.Action == "asset_review_pending" && r.State != accessreviews.StatePending {
					return false, nil
				}
				return id == r.OwnerID || p.Allows("reviews.login.manage"), nil
			}})
	}
	if d.Jobs != nil {
		out = append(out, notifications.Feed{Name: "job-security", Read: d.Jobs.SecurityNotificationFeed, Link: link("job-security"),
			Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(u coreauth.User, p rbac.Snapshot) []string {
					topics := []string{}
					if e.State == "job_review_pending" {
						if u.ID == e.OwnerID {
							topics = append(topics, "security")
						}
						if p.Allows("jobs.review") {
							topics = append(topics, "approvals")
						}
					} else if u.ID == e.OwnerID || p.Allows("jobs.view_all") {
						topics = append(topics, "security")
					}
					return topics
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				_, p, ok := notificationActor(ctx, d, id)
				if !ok {
					return false, ctx.Err()
				}
				r, e := d.Jobs.SecurityNotificationInfo(source.ID)
				if errors.Is(e, jobs.ErrNotFound) {
					return false, nil
				}
				if e != nil {
					return false, e
				}
				if source.Action == "review" {
					return p.Allows("jobs.review") && r.State == "pending_review", nil
				}
				if source.Action == "job_review_pending" && r.State != "pending_review" {
					return false, nil
				}
				return id == r.OwnerID || p.Allows("jobs.view_all"), nil
			}})
	}
	if d.Sessions != nil {
		out = append(out, notifications.Feed{Name: "command-reviews", Read: d.Sessions.NotificationFeed, Link: link("command-reviews"),
			Recipients: func(ctx context.Context, _ eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(_ coreauth.User, p rbac.Snapshot) []string {
					if p.Allows("reviews.command.manage") {
						return []string{"approvals"}
					}
					return nil
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				_, p, ok := notificationActor(ctx, d, id)
				return ok && p.Allows("reviews.command.manage") && d.Sessions.NotificationPending(source.ID), ctx.Err()
			}})
	}
	if d.CommandAlerts != nil {
		out = append(out, notifications.Feed{Name: "command-alerts", Read: d.CommandAlerts.NotificationFeed, Link: link("command-alerts"),
			Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(u coreauth.User, p rbac.Snapshot) []string {
					if u.ID == e.OwnerID || u.ID == e.ActorID || p.Allows("audit.commands.view_all") {
						return []string{"security"}
					}
					return nil
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				_, p, ok := notificationActor(ctx, d, id)
				if !ok {
					return false, ctx.Err()
				}
				r, err := d.CommandAlerts.Get(source.ID)
				if errors.Is(err, commandalerts.ErrNotFound) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				if source.Action == "command_review_pending" && (d.Sessions == nil || !d.Sessions.NotificationPending("command-review-"+r.ReviewID)) {
					return false, nil
				}
				return id == r.OwnerID || id == r.ActorID || p.Allows("audit.commands.view_all"), nil
			}})
	}
	if d.AgentEvents != nil {
		out = append(out, notifications.Feed{Name: "agent-events", Read: d.AgentEvents.NotificationFeed, Link: link("agent-events"),
			Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(u coreauth.User, p rbac.Snapshot) []string {
					if u.ID == e.OwnerID || p.Allows("audit.agents.view_all") {
						return []string{"security"}
					}
					return nil
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				u, _, ok := notificationActor(ctx, d, id)
				if !ok {
					return false, ctx.Err()
				}
				r, e := d.AgentEvents.NotificationSource(source.ID)
				if errors.Is(e, agentevents.ErrNotificationNotFound) {
					return false, nil
				}
				if e != nil {
					return false, e
				}
				return agentSourceAllowed(d, u, r.Source), nil
			}})
	}
	if d.AccountRisks != nil {
		out = append(out, notifications.Feed{Name: "account-risks", Read: d.AccountRisks.NotificationFeed, Link: link("account-risks"),
			Recipients: func(ctx context.Context, _ eventfeed.Event) ([]notifications.Recipient, error) {
				return notificationAudience(ctx, d, func(_ coreauth.User, p rbac.Snapshot) []string {
					if p.Allows("accounts.risks.view") && (p.Allows("assets.view_all") || p.Allows("assets.manage")) {
						return []string{"security"}
					}
					return nil
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				_, p, ok := notificationActor(ctx, d, id)
				if !ok {
					return false, ctx.Err()
				}
				_, exists := d.AccountRisks.ScanRecord(source.ID)
				return exists && p.Allows("accounts.risks.view") && (p.Allows("assets.view_all") || p.Allows("assets.manage")), nil
			}})
	}
	if d.MonitorAlerts != nil {
		out = append(out, notifications.Feed{Name: "monitor-alerts", Read: d.MonitorAlerts.NotificationFeed, Link: func(e eventfeed.Event) string { return "/console/monitoring?alert=" + url.QueryEscape(e.ResourceID) },
			Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
				a, err := d.MonitorAlerts.Alert(e.ResourceID)
				if errors.Is(err, monitoralerts.ErrNotFound) {
					return []notifications.Recipient{}, nil
				}
				if err != nil {
					return nil, err
				}
				return notificationAudience(ctx, d, func(u coreauth.User, p rbac.Snapshot) []string {
					if p.Allows("monitoring.view") && monitorVisible(d, u, p, a.AssetID) {
						return []string{"security"}
					}
					return nil
				})
			}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
				a, err := d.MonitorAlerts.Alert(source.ID)
				if errors.Is(err, monitoralerts.ErrNotFound) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				return monitorNotificationAllowed(ctx, d, id, a, source.Action), ctx.Err()
			}})
	}
	return out
}
