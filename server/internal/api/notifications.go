package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
)

func notificationPrincipal(ctx context.Context, d Dependencies, id string) (notifications.Principal, error) {
	if ctx.Err() != nil {
		return notifications.Principal{}, ctx.Err()
	}
	u, ok := jobOwner(d, id)
	if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
		return notifications.Principal{}, notifications.ErrDenied
	}
	p := effectivePermissions(u, d.RBAC, d.Groups)
	if d.PlatformNotifications {
		var ok bool
		u, p, ok = globalLoginActor(d, id)
		if !ok {
			return notifications.Principal{}, notifications.ErrDenied
		}
	}
	return notifications.Principal{Actor: notifications.Actor{ID: u.ID, Name: u.Username}, CanManage: p.Allows("notifications.manage"), CanAudit: p.Allows("notifications.audit"), CanRetry: p.Allows("notifications.retry")}, nil
}
func notificationError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, notifications.ErrInvalid):
		status, code = 400, "invalid"
	case errors.Is(e, notifications.ErrDenied):
		status, code = 403, "denied"
	case errors.Is(e, notifications.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, notifications.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(e, notifications.ErrVerification):
		status, code = 409, "verification_required"
	case errors.Is(e, notifications.ErrRateLimit):
		status, code = 429, "rate_limit"
	case errors.Is(e, notifications.ErrCapacity):
		status, code = 429, "capacity"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func registerNotificationRoutes(mux *http.ServeMux, d Dependencies) {
	if d.Notifications == nil || d.Auth == nil {
		return
	}
	s := d.Notifications
	runner := notifications.Runner{SiteURL: d.PublicURL, OrganizationID: d.OrganizationID, Send: notifications.TransportSend, Principal: func(ctx context.Context, id string) (notifications.Principal, error) {
		return notificationPrincipal(ctx, d, id)
	}}
	if d.Tickets != nil {
		runner.Feeds = append(runner.Feeds, notifications.Feed{Name: "tickets", Read: d.Tickets.NotificationFeed, Recipients: func(ctx context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
			rows, err := d.Tickets.NotificationRecipients(ctx, e)
			out := []notifications.Recipient{}
			for _, v := range rows {
				out = append(out, notifications.Recipient{UserID: v.UserID, Topic: v.Topic})
			}
			return out, err
		}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
			ok, e := d.Tickets.NotificationAllowed(ctx, id, source.ID, source.Revision, source.Action == "review")
			if errors.Is(e, tickets.ErrNotFound) || errors.Is(e, tickets.ErrDenied) {
				return false, nil
			}
			return ok, e
		}, Link: func(e eventfeed.Event) string {
			return "/console/access-tickets?request=" + url.QueryEscape(e.ResourceID)
		}})
	}
	if d.Jobs != nil {
		runner.Feeds = append(runner.Feeds, notifications.Feed{Name: "jobs", Read: d.Jobs.NotificationFeed, Recipients: func(_ context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
			return []notifications.Recipient{{UserID: e.OwnerID, Topic: "jobs"}}, nil
		}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
			owner, e := d.Jobs.NotificationOwner(source.ID)
			if errors.Is(e, jobs.ErrNotFound) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			u, ok := jobOwner(d, id)
			if !ok {
				return false, nil
			}
			return owner == id || effectivePermissions(u, d.RBAC, d.Groups).Allows("jobs.view_all"), ctx.Err()
		}, Link: func(e eventfeed.Event) string { return "/workbench?job=" + url.QueryEscape(e.ResourceID) }})
	}
	if d.RotationPlans != nil {
		runner.Feeds = append(runner.Feeds, notifications.Feed{Name: "rotation", Read: d.RotationPlans.NotificationFeed, Recipients: func(_ context.Context, e eventfeed.Event) ([]notifications.Recipient, error) {
			return []notifications.Recipient{{UserID: e.OwnerID, Topic: "rotation"}}, nil
		}, Allowed: func(ctx context.Context, id string, source notifications.Source) (bool, error) {
			_, e := d.RotationPlans.NotificationOwner(source.ID)
			if errors.Is(e, rotationplans.ErrNotFound) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			u, ok := jobOwner(d, id)
			if !ok {
				return false, nil
			}
			p := effectivePermissions(u, d.RBAC, d.Groups)
			return p.Allows("accounts.rotation.view") && p.Allows("assets.view_all"), ctx.Err()
		}, Link: func(e eventfeed.Event) string { return "/console/rotation-plans?run=" + url.QueryEscape(e.ResourceID) }})
	}
	runner.Feeds = append(runner.Feeds, securityNotificationFeeds(d)...)
	if d.PlatformNotifications {
		runner.Feeds = platformLoginNotificationFeeds(d)
	}
	s.SetRunner(runner)
	handle := func(pattern string, h func(http.ResponseWriter, *http.Request, string)) {
		mux.Handle(pattern, protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			u, ok := PrincipalFromContext(r.Context())
			if !ok {
				notificationError(w, notifications.ErrDenied)
				return
			}
			if _, e := notificationPrincipal(r.Context(), d, u.ID); e != nil {
				notificationError(w, e)
				return
			}
			h(w, r, u.ID)
		}), d.AdminToken, d.Auth))
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
			notificationError(w, notifications.ErrInvalid)
			return false
		}
		return true
	}
	respond := func(w http.ResponseWriter, v any, e error) {
		if e != nil {
			notificationError(w, e)
		} else {
			writeJSON(w, 200, v)
		}
	}
	paging := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			notificationError(w, notifications.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	base := "/api/v1/notifications"
	if d.PlatformNotifications {
		base = "/api/v1/platform-notifications"
	}
	handle("GET "+base+"/capabilities", func(w http.ResponseWriter, r *http.Request, id string) {
		p, e := notificationPrincipal(r.Context(), d, id)
		if e != nil {
			notificationError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"manage": p.CanManage, "audit": p.CanAudit, "retry": p.CanRetry, "platform": d.PlatformNotifications})
	})
	handle("GET "+base+"/sources/{kind}/{id}", func(w http.ResponseWriter, r *http.Request, id string) {
		out, e := notificationSourceDetails(r.Context(), d, id, r.PathValue("kind"), r.PathValue("id"))
		respond(w, out, e)
	})
	handle("GET "+base+"/inbox", func(w http.ResponseWriter, r *http.Request, id string) {
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		unread := r.URL.Query().Get("unread")
		if unread != "" && unread != "true" && unread != "false" {
			notificationError(w, notifications.ErrInvalid)
			return
		}
		v, count, e := s.Inbox(r.Context(), id, unread == "true", offset, limit)
		respond(w, map[string]any{"results": v.Results, "total": v.Total, "unread": count}, e)
	})
	handle("POST "+base+"/read", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			ID  string `json:"id"`
			All bool   `json:"all"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.All && in.ID != "" || !in.All && in.ID == "" {
			notificationError(w, notifications.ErrInvalid)
			return
		}
		respond(w, map[string]bool{"ok": true}, s.Read(r.Context(), id, in.ID, in.All))
	})
	handle("GET "+base+"/preferences", func(w http.ResponseWriter, r *http.Request, id string) {
		v, e := s.Preferences(r.Context(), id)
		respond(w, v, e)
	})
	handle("PUT "+base+"/preferences", func(w http.ResponseWriter, r *http.Request, id string) {
		var in notifications.PreferencesInput
		if !decode(w, r, &in) {
			return
		}
		v, e := s.SavePreferences(r.Context(), id, in)
		respond(w, v, e)
	})
	handle("POST "+base+"/locale", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			Language string `json:"language"`
		}
		if !decode(w, r, &in) {
			return
		}
		respond(w, map[string]bool{"ok": true}, s.DetectLanguage(r.Context(), id, in.Language))
	})
	handle("POST "+base+"/verification/request", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			Channel string `json:"channel"`
		}
		if !decode(w, r, &in) {
			return
		}
		v, e := s.RequestVerification(r.Context(), id, in.Channel)
		respond(w, v, e)
	})
	handle("POST "+base+"/verification/confirm", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			Channel string `json:"channel"`
			Code    string `json:"code"`
		}
		if !decode(w, r, &in) {
			return
		}
		v, e := s.Verify(r.Context(), id, in.Channel, in.Code)
		respond(w, v, e)
	})
	handle("GET "+base+"/settings", func(w http.ResponseWriter, r *http.Request, id string) {
		v, e := s.Settings(r.Context(), id)
		respond(w, v, e)
	})
	handle("PUT "+base+"/settings", func(w http.ResponseWriter, r *http.Request, id string) {
		var in notifications.SettingsInput
		if !decode(w, r, &in) {
			return
		}
		v, e := s.SaveSettings(r.Context(), id, in)
		respond(w, v, e)
	})
	handle("POST "+base+"/test", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			RequestID string `json:"request_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		v, e := s.Test(r.Context(), id, in.RequestID)
		respond(w, v, e)
	})
	handle("GET "+base+"/deliveries", func(w http.ResponseWriter, r *http.Request, id string) {
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		v, e := s.Deliveries(r.Context(), id, r.URL.Query().Get("state"), offset, limit)
		respond(w, v, e)
	})
	handle("POST "+base+"/deliveries/{id}/retry", func(w http.ResponseWriter, r *http.Request, id string) {
		var in struct {
			Revision    int  `json:"revision"`
			Acknowledge bool `json:"acknowledge_uncertain"`
		}
		if !decode(w, r, &in) {
			return
		}
		v, e := s.Retry(r.Context(), id, r.PathValue("id"), in.Revision, in.Acknowledge)
		respond(w, v, e)
	})
	handle("GET "+base+"/audit", func(w http.ResponseWriter, r *http.Request, id string) {
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		v, e := s.Audit(r.Context(), id, offset, limit)
		respond(w, v, e)
	})
	handle("GET "+base+"/health", func(w http.ResponseWriter, r *http.Request, id string) {
		v, e := s.Health(r.Context(), id)
		respond(w, v, e)
	})
}
