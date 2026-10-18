package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func reportError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	if errors.Is(e, reporting.ErrInvalid) {
		status, code = 400, "invalid"
	}
	if errors.Is(e, reporting.ErrDenied) {
		status, code = 403, "denied"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func reportQuery(r *http.Request) (reporting.Query, error) {
	now := time.Now().UTC()
	q := reporting.Query{From: now.AddDate(0, 0, -7).Truncate(24 * time.Hour), To: now, Sources: []string{}}
	var e error
	values := r.URL.Query()
	for _, field := range []string{"from", "to"} {
		if raw := values.Get(field); raw != "" {
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return q, reporting.ErrInvalid
			}
			if field == "from" {
				q.From = t
			} else {
				q.To = t
			}
		}
	}
	if raw := values.Get("include_platform"); raw != "" {
		q.IncludePlatform, e = strconv.ParseBool(raw)
		if e != nil {
			return q, reporting.ErrInvalid
		}
	}
	if raw := values.Get("sources"); raw != "" {
		q.Sources = strings.Split(raw, ",")
	}
	return q, reporting.Validate(q, now)
}
func reportAuthority(d Dependencies, u coreauth.User, p rbac.Snapshot) string {
	// Scope and role changes cannot reuse a stale aggregation after collection.
	raw, _ := json.Marshal(struct {
		User               string
		Permissions, Roles []string
		Global             rbac.Snapshot
	}{u.ID, p.Permissions, p.RoleIDs, globalLoginPermissions(d, u)})
	return string(raw)
}
func registerReportRoutes(mux *http.ServeMux, d Dependencies, mu *sync.RWMutex) {
	if d.Reports == nil || d.Auth == nil || d.Assets == nil {
		return
	}
	protect := func(fn func(http.ResponseWriter, *http.Request, coreauth.User, rbac.Snapshot)) http.Handler {
		return protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setNoStore(w)
			principal, _ := PrincipalFromContext(r.Context())
			u, p, ok := notificationActor(r.Context(), d, principal.ID)
			if !ok {
				reportError(w, reporting.ErrDenied)
				return
			}
			fn(w, r, u, p)
		}), d.AdminToken, d.Auth)
	}
	lock := func() func() {
		global := d.GlobalAccessMu
		if global != nil && global != mu {
			global.RLock()
		}
		mu.RLock()
		return func() {
			mu.RUnlock()
			if global != nil && global != mu {
				global.RUnlock()
			}
		}
	}
	collect := func(r *http.Request, u coreauth.User, p rbac.Snapshot) (reporting.Report, error) {
		q, e := reportQuery(r)
		if e != nil {
			return reporting.Report{}, e
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		sources := reportSources(ctx, d, u, p, q)
		out, e := reporting.Build(ctx, q, sources, time.Now().UTC())
		if e != nil {
			return out, e
		}
		fresh, permissions, ok := notificationActor(r.Context(), d, u.ID)
		if !ok || reportAuthority(d, u, p) != reportAuthority(d, fresh, permissions) {
			return out, reporting.ErrDenied
		}
		return out, nil
	}
	mux.Handle("GET /api/v1/reports/capabilities", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		writeJSON(w, 200, map[string]bool{"export": p.Allows("reports.export"), "audit_all": p.Allows("reports.audit")})
	}))
	mux.Handle("GET /api/v1/reports/overview", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		release := lock()
		defer release()
		out, e := collect(r, u, p)
		if e != nil {
			reportError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/reports/export.csv", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		if !p.Allows("reports.export") {
			reportError(w, reporting.ErrDenied)
			return
		}
		release := lock()
		defer func() {
			if release != nil {
				release()
			}
		}()
		out, e := collect(r, u, p)
		if e != nil {
			reportError(w, e)
			return
		}
		if out.Partial && r.URL.Query().Get("allow_partial") != "true" {
			writeJSON(w, 409, map[string]string{"error_code": "partial"})
			return
		}
		var csv bytes.Buffer
		if e = reporting.CSV(&csv, out); e != nil || csv.Len() > reporting.MaxCSVBytes {
			reportError(w, reporting.ErrLimit)
			return
		}
		fresh, current, ok := notificationActor(r.Context(), d, u.ID)
		if !ok || !current.Allows("reports.export") || reportAuthority(d, u, p) != reportAuthority(d, fresh, current) {
			reportError(w, reporting.ErrDenied)
			return
		}
		receipt, e := d.Reports.Commit(u.ID, out, csv.Bytes())
		if e != nil {
			reportError(w, e)
			return
		}
		release()
		release = nil
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="operations-report.csv"`)
		w.Header().Set("X-JMS-Report-ID", receipt.ID)
		w.Header().Set("X-JMS-Report-SHA256", receipt.SHA256)
		_, _ = w.Write(csv.Bytes())
	}))
	mux.Handle("GET /api/v1/reports/exports", protect(func(w http.ResponseWriter, r *http.Request, u coreauth.User, p rbac.Snapshot) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		scope := defaultQuery(r, "scope", "mine")
		if e != nil || e2 != nil || !slices.Contains([]string{"mine", "all"}, scope) {
			reportError(w, reporting.ErrInvalid)
			return
		}
		if scope == "all" && !p.Allows("reports.audit") {
			reportError(w, reporting.ErrDenied)
			return
		}
		rows, total, e := d.Reports.List(u.ID, scope == "all", offset, limit)
		if e != nil {
			reportError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
}
