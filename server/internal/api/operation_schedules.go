package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type calendarAuthorize func(coreauth.User, string, string, accesspolicies.Origin) (string, string, commandfilters.Decision, int)

func lockCalendarAccess(d Dependencies, mu *sync.RWMutex) func() {
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
func authorizeCalendarOwner(d Dependencies, p operations.Plan, authorize calendarAuthorize) bool {
	return authorizeOperationOwner(d, p, authorize, true)
}
func authorizeOperationOwner(d Dependencies, p operations.Plan, authorize calendarAuthorize, scheduled bool) bool {
	owner, ok := jobOwner(d, p.OwnerID)
	if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(owner) {
		return false
	}
	origin := p.AccessOrigin
	if scheduled {
		origin.Method = "scheduled_exec"
	}
	for _, id := range p.AssetIDs {
		_, _, decision, status := authorize(owner, id, p.Command, origin)
		deferredDirectory := decision.DirectoryRequired && operationDirectoryProofPossible(d, id, p.WorkingDirectory)
		if status != http.StatusOK || validateOperationDirectoryAsset(d, id, p.WorkingDirectory) != nil || p.ProgramID == "" && !decision.Allowed && !deferredDirectory {
			return false
		}
	}
	return true
}
func registerCalendarRoutes(mux *http.ServeMux, d Dependencies, authorize calendarAuthorize, mu *sync.RWMutex) {
	protect := func(fn http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(fn, d.AdminToken, d.Auth) }
	readPlan := func(w http.ResponseWriter, r *http.Request, manage bool) (operations.Plan, coreauth.User, bool) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		p, e := d.Operations.Plan(r.PathValue("planID"))
		allowed := u.ID == p.OwnerID || hasPermission(r, "plans.manage_all") || !manage && hasPermission(r, "plans.view_all")
		if e != nil || !allowed {
			writeJobError(w, operations.ErrNotFound)
			return p, u, false
		}
		return p, u, true
	}
	mux.Handle("POST /api/v1/ops/schedules/preview", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in operations.PreviewInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		out, e := operations.PreviewSchedule(in, time.Now().UTC())
		if e != nil {
			writeJobError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("GET /api/v1/ops/plans/{planID}", protect(func(w http.ResponseWriter, r *http.Request) {
		p, _, ok := readPlan(w, r, false)
		if ok {
			writeJSON(w, 200, p)
		}
	}))
	mux.Handle("GET /api/v1/ops/plans/{planID}/events", protect(func(w http.ResponseWriter, r *http.Request) {
		p, _, ok := readPlan(w, r, false)
		if !ok {
			return
		}
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		rows, total, e := d.Operations.ScheduleEvents(p.ID, offset, limit)
		if e != nil {
			writeJobError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": total})
	}))
	mux.Handle("PUT /api/v1/ops/plans/{planID}/schedule", protect(func(w http.ResponseWriter, r *http.Request) {
		var in operations.ScheduleUpdate
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		p, u, ok := readPlan(w, r, true)
		if !ok {
			return
		}
		release := lockCalendarAccess(d, mu)
		defer release()
		if !authorizeCalendarOwner(d, p, authorize) {
			writeJobError(w, operations.ErrDenied)
			return
		}
		out, e := d.Operations.UpdateSchedule(p.ID, in, operations.ScheduleActor{ID: u.ID, Name: u.Username})
		if e != nil {
			writeJobError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
}
