package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
)

func registerOrganizationOverview(mux *http.ServeMux, d Dependencies) {
	if d.Tenant || d.Auth == nil || d.Organizations == nil {
		return
	}
	slots := make(chan struct{}, 4)
	mux.Handle("GET /api/v1/organizations/overview", protectAuthenticatedAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, ok := PrincipalFromContext(r.Context())
		authority := func(user coreauth.User) string {
			p := globalLoginPermissions(d, user)
			if !p.Allows("organizations.overview") {
				return ""
			}
			raw, _ := json.Marshal(struct {
				User        coreauth.User
				Permissions any
			}{user, p})
			return string(raw)
		}
		if !ok {
			writeJSON(w, 401, map[string]string{"error_code": "organization_overview_denied"})
			return
		}
		initial := authority(u)
		if initial == "" {
			writeJSON(w, 403, map[string]string{"error_code": "organization_overview_denied"})
			return
		}
		query := r.URL.Query()
		for key, values := range query {
			if key != "include_archived" || len(values) != 1 {
				writeJSON(w, 400, map[string]string{"error_code": "organization_overview_invalid"})
				return
			}
		}
		archived := false
		if raw := query.Get("include_archived"); raw != "" {
			var err error
			archived, err = strconv.ParseBool(raw)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error_code": "organization_overview_invalid"})
				return
			}
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeJSON(w, 429, map[string]string{"error_code": "organization_overview_busy"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		active := d.Auth.ActiveUsersSnapshot()
		ids := make([]string, 0, len(active))
		for _, user := range active {
			ids = append(ids, user.ID)
		}
		rows := d.Organizations.OverviewMetadata(archived, ids)
		collect := d.OrganizationCounts
		if collect == nil {
			collect = func(context.Context, string) (organizations.ResourceCounts, error) {
				return organizations.ResourceCounts{}, organizations.ErrOverviewUnavailable
			}
		}
		out, err := organizations.BuildOverview(ctx, rows, collect, time.Now())
		if err != nil {
			writeJSON(w, 503, map[string]string{"error_code": "organization_overview_unavailable"})
			return
		}
		// Recheck the authenticated credential as well as current global authority.
		// A local organization role cannot confer this system-wide permission.
		mu := d.GlobalAccessMu
		if mu == nil {
			mu = d.AccessMu
		}
		if mu != nil {
			mu.RLock()
			defer mu.RUnlock()
		}
		fresh, status := resolvePrincipal(r, d.AdminToken, d.Auth)
		if status != 200 || authority(fresh) != initial {
			writeJSON(w, 403, map[string]string{"error_code": "organization_overview_denied"})
			return
		}
		writeJSON(w, 200, out)
	}), d.AdminToken, d.Auth))
}
