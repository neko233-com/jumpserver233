package api

import (
	"bytes"
	"encoding/csv"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginaudit"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var errLoginAuditDenied = errors.New("platform login audit denied")

func loginAuditError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, loginaudit.ErrInvalid):
		status, code = 400, "invalid"
	case errors.Is(e, loginaudit.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, errLoginAuditDenied):
		status, code = 403, "denied"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func globalLoginActor(d Dependencies, id string) (coreauth.User, rbac.Snapshot, bool) {
	u, ok := jobOwner(d, id)
	if !ok {
		return u, rbac.Snapshot{}, false
	}
	return u, globalLoginPermissions(d, u), true
}
func globalLoginPermissions(d Dependencies, u coreauth.User) rbac.Snapshot {
	roles, groups := d.GlobalRBAC, d.GlobalGroups
	if roles == nil {
		roles = d.RBAC
		groups = d.Groups
	}
	return effectivePermissions(u, roles, groups)
}
func canReviewPlatformLogin(d Dependencies, u coreauth.User, p rbac.Snapshot, id string) bool {
	if d.LoginReviews == nil || !p.Allows("reviews.platform_login.manage") {
		return false
	}
	v, e := d.LoginReviews.Get(id)
	if e != nil || v.State != loginreviews.Pending || v.UserID == u.ID {
		return false
	}
	var groups []string
	if d.GlobalGroups != nil {
		groups = d.GlobalGroups.GroupIDsForUser(u.ID)
	} else if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	return loginreviews.ReviewerAllowed(v, u.ID, groups)
}
func canReadLoginAudit(d Dependencies, u coreauth.User, p rbac.Snapshot, r loginaudit.Record) bool {
	return r.UserID == u.ID || p.Allows("audit.logins.view_all") || r.Stage == "review" && r.Outcome == "review_pending" && canReviewPlatformLogin(d, u, p, r.ReviewID)
}
func registerLoginAuditRoutes(mux *http.ServeMux, d Dependencies) {
	if d.LoginAudit == nil || d.Auth == nil || d.Tenant {
		return
	}
	protect := func(h func(http.ResponseWriter, *http.Request, coreauth.User, rbac.Snapshot)) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, _ := PrincipalFromContext(r.Context())
			u, p, ok := globalLoginActor(d, actor.ID)
			if !ok {
				loginAuditError(w, errLoginAuditDenied)
				return
			}
			setNoStore(w)
			h(w, r, u, p)
		}), d.AdminToken, d.Auth)
	}
	parse := func(r *http.Request, p rbac.Snapshot, export bool) (loginaudit.Filter, bool, error) {
		q := r.URL.Query()
		f := loginaudit.Filter{Method: q.Get("method"), Outcome: q.Get("outcome"), Query: q.Get("q"), SourceIP: q.Get("source_ip"), UserID: q.Get("user_id"), Limit: 25}
		scope := q.Get("scope")
		all := scope == "all"
		if scope != "" && scope != "mine" && !all {
			return f, false, loginaudit.ErrInvalid
		}
		if all && !p.Allows("audit.logins.view_all") || export && all && !p.Allows("audit.logins.export") {
			return f, all, errLoginAuditDenied
		}
		if export {
			f.Limit = loginaudit.MaxRecords
		}
		var e error
		if v := q.Get("offset"); v != "" {
			f.Offset, e = strconv.Atoi(v)
		}
		if e == nil && !export {
			if v := q.Get("limit"); v != "" {
				f.Limit, e = strconv.Atoi(v)
			}
		}
		if e == nil {
			if v := q.Get("from"); v != "" {
				f.From, e = time.Parse(time.RFC3339, v)
			}
		}
		if e == nil {
			if v := q.Get("to"); v != "" {
				f.To, e = time.Parse(time.RFC3339, v)
			}
		}
		if e != nil {
			return f, all, loginaudit.ErrInvalid
		}
		return f, all, nil
	}
	respond := func(w http.ResponseWriter, v any, e error) {
		if e != nil {
			loginAuditError(w, e)
			return
		}
		writeJSON(w, 200, v)
	}
	mux.Handle("GET /api/v1/audits/logins/capabilities", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		writeJSON(w, 200, map[string]bool{"view_all": p.Allows("audit.logins.view_all"), "export_all": p.Allows("audit.logins.view_all") && p.Allows("audit.logins.export")})
	}))
	mux.Handle("GET /api/v1/audits/logins", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		f, all, e := parse(r, p, false)
		if e != nil {
			respond(w, nil, e)
			return
		}
		out, e := d.LoginAudit.List(f, func(v loginaudit.Record) bool { return all || v.UserID == u.ID })
		respond(w, out, e)
	}))
	mux.Handle("GET /api/v1/audits/logins/summary", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		f, all, e := parse(r, p, false)
		if e != nil {
			respond(w, nil, e)
			return
		}
		out, e := d.LoginAudit.Summary(f, func(v loginaudit.Record) bool { return all || v.UserID == u.ID })
		respond(w, out, e)
	}))
	mux.Handle("GET /api/v1/audits/logins/health", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		if !p.Allows("audit.logins.view_all") {
			respond(w, nil, errLoginAuditDenied)
			return
		}
		writeJSON(w, 200, d.LoginAudit.Health())
	}))
	mux.Handle("GET /api/v1/audits/logins/{eventID}", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		row, e := d.LoginAudit.Get(r.PathValue("eventID"))
		if e != nil {
			respond(w, nil, e)
			return
		}
		if !canReadLoginAudit(d, u, p, row) {
			respond(w, nil, loginaudit.ErrNotFound)
			return
		}
		out := struct {
			loginaudit.Record
			ReviewState     string    `json:"review_state,omitempty"`
			CanReview       bool      `json:"can_review"`
			ReviewExpiresAt time.Time `json:"review_expires_at,omitzero"`
		}{Record: row}
		if row.ReviewID != "" && d.LoginReviews != nil {
			if review, e := d.LoginReviews.Get(row.ReviewID); e == nil {
				out.ReviewState = review.State
				out.ReviewExpiresAt = review.ExpiresAt
				out.CanReview = canReviewPlatformLogin(d, u, p, review.ID)
			}
		}
		respond(w, out, nil)
	}))
	mux.Handle("GET /api/v1/audits/logins/export.csv", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		f, all, e := parse(r, p, true)
		if e != nil {
			respond(w, nil, e)
			return
		}
		f.Offset = 0
		rows, e := d.LoginAudit.Export(f, func(v loginaudit.Record) bool { return all || v.UserID == u.ID })
		if e != nil {
			respond(w, nil, e)
			return
		}
		_, permissions, ok := globalLoginActor(d, u.ID)
		if !ok || all && (!permissions.Allows("audit.logins.view_all") || !permissions.Allows("audit.logins.export")) {
			respond(w, nil, errLoginAuditDenied)
			return
		}
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)
		_ = writer.Write([]string{"id", "sequence", "time", "method", "stage", "outcome", "reason", "user_id", "username", "attempted_name", "source_ip", "client", "review_id", "actor_id"})
		cell := func(v string) string {
			if len(v) > 0 && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
				return "'" + v
			}
			return v
		}
		for _, v := range rows.Results {
			if r.Context().Err() != nil {
				return
			}
			_ = writer.Write([]string{v.ID, strconv.FormatUint(v.Sequence, 10), v.At.Format(time.RFC3339Nano), v.Method, v.Stage, v.Outcome, v.Reason, v.UserID, cell(v.Username), cell(v.AttemptedName), v.SourceIP, v.Client, v.ReviewID, v.ActorID})
		}
		writer.Flush()
		if writer.Error() != nil {
			loginAuditError(w, writer.Error())
			return
		}
		if _, e = d.LoginAudit.Append(loginaudit.Input{Method: "unknown", Stage: "export", Outcome: "exported", UserID: u.ID, Username: u.Username, SourceIP: accesspolicies.SourceIP(r.Context()), Client: "api"}); e != nil {
			loginAuditError(w, e)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="platform-login-audit.csv"`)
		_, _ = w.Write(buf.Bytes())
	}))
}
