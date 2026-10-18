package api

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"net/http"
	"strconv"
	"sync"
)

func writePlaybookError(w http.ResponseWriter, e error) {
	var issue *playbooks.Issue
	if errors.As(e, &issue) {
		writeJSON(w, 400, map[string]any{"error_code": "playbook_invalid", "issue": issue})
		return
	}
	if errors.Is(e, playbooks.ErrInvalid) {
		writeJSON(w, 400, map[string]string{"error_code": "playbook_invalid"})
		return
	}
	writeJobError(w, e)
}
func registerPlaybookRoutes(mux *http.ServeMux, d Dependencies, authorize calendarAuthorize, mu *sync.RWMutex) {
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	page := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil {
			writeJobError(w, operations.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	d.Operations.SetPlaybookAuthorizer(func(ownerID, asset string, origin accesspolicies.Origin) error {
		release := lockCalendarAccess(d, mu)
		defer release()
		owner, ok := jobOwner(d, ownerID)
		if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(owner) {
			return operations.ErrDenied
		}
		_, _, _, status := authorize(owner, asset, "", origin)
		if status != http.StatusOK {
			return operations.ErrDenied
		}
		return nil
	})
	mux.Handle("GET /api/v1/ops/playbooks/capabilities", protect(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeJSON(w, 200, map[string]any{"format": "jms233-native-v1", "modules": playbooks.Modules(), "max_files": playbooks.MaxFiles, "max_file_bytes": playbooks.MaxFileBytes, "max_workspace_bytes": playbooks.MaxWorkspaceBytes, "max_tasks": playbooks.MaxTasks, "max_expanded_tasks": playbooks.MaxExpandedTasks, "max_run_steps": 2000, "max_retained_steps": 20000, "remote_platform": "linux", "controller_lookups": false})
	}))
	mux.Handle("POST /api/v1/ops/playbooks/validate", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in playbooks.Workspace
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		p, e := playbooks.Compile(in)
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		type summary struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Module  string `json:"module"`
			File    string `json:"file"`
			Line    int    `json:"line"`
			Handler bool   `json:"handler"`
		}
		rows := []summary{}
		for _, t := range p.Tasks {
			rows = append(rows, summary{t.ID, t.Name, t.Module, t.File, t.Line, t.Handler})
		}
		writeJSON(w, 200, map[string]any{"valid": true, "program_id": playbooks.WorkspaceID(p.Files), "tasks": rows, "max_steps": p.MaxSteps})
	}))
	mux.Handle("GET /api/v1/ops/playbooks", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		rows, n, e := d.Operations.Playbooks(user.ID, offset, limit)
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": n})
	}))
	mux.Handle("GET /api/v1/ops/playbooks/{playbookID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		user, _ := PrincipalFromContext(r.Context())
		out, e := d.Operations.Playbook(r.PathValue("playbookID"), user.ID)
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in operations.PlaybookInput
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		release := lockCalendarAccess(d, mu)
		defer release()
		out, e := d.Operations.SavePlaybook(r.PathValue("playbookID"), user.ID, user.Username, in, hasPermission(r, "playbooks.publish"))
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		status := 200
		if r.Method == "POST" {
			status = 201
		}
		writeJSON(w, status, out)
	}
	mux.Handle("POST /api/v1/ops/playbooks", protect(save))
	mux.Handle("PUT /api/v1/ops/playbooks/{playbookID}", protect(save))
	mux.Handle("DELETE /api/v1/ops/playbooks/{playbookID}", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		revision, e := strconv.Atoi(r.URL.Query().Get("revision"))
		if e != nil || revision < 1 {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		if e = d.Operations.DeletePlaybook(r.PathValue("playbookID"), user.ID, revision); e != nil {
			writePlaybookError(w, e)
			return
		}
		w.WriteHeader(204)
	}))
	mux.Handle("GET /api/v1/ops/playbooks/{playbookID}/events", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		offset, limit, ok := page(w, r)
		if !ok {
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		rows, n, e := d.Operations.PlaybookEvents(r.PathValue("playbookID"), user.ID, offset, limit)
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"results": rows, "total": n})
	}))
	readRun := func(w http.ResponseWriter, r *http.Request) (operations.Run, bool) {
		setNoStore(w)
		user, _ := PrincipalFromContext(r.Context())
		run, e := d.Operations.Run(r.PathValue("runID"))
		if e != nil || run.OwnerID != user.ID && !hasPermission(r, "plans.view_all") && !hasPermission(r, "plans.manage_all") {
			writeJobError(w, operations.ErrNotFound)
			return run, false
		}
		return run, true
	}
	mux.Handle("GET /api/v1/ops/runs/{runID}/program", protect(func(w http.ResponseWriter, r *http.Request) {
		run, ok := readRun(w, r)
		if !ok {
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		p, e := d.Operations.RunProgram(run.ID, user.ID, hasPermission(r, "plans.view_all") || hasPermission(r, "plans.manage_all"))
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 200, p)
	}))
	mux.Handle("GET /api/v1/ops/runs/{runID}/steps/{assetID}/{stepID}", protect(func(w http.ResponseWriter, r *http.Request) {
		run, ok := readRun(w, r)
		if !ok {
			return
		}
		user, _ := PrincipalFromContext(r.Context())
		if user.ID != run.OwnerID && !hasPermission(r, "jobs.view_all") {
			writeJobError(w, operations.ErrDenied)
			return
		}
		out, e := d.Operations.StepOutput(run.ID, r.PathValue("assetID"), r.PathValue("stepID"))
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /api/v1/ops/plans/{planID}/runs", protect(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		var in struct {
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil {
			writeJobError(w, operations.ErrInvalid)
			return
		}
		p, e := d.Operations.Plan(r.PathValue("planID"))
		user, _ := PrincipalFromContext(r.Context())
		if e != nil || p.OwnerID != user.ID && !hasPermission(r, "plans.manage_all") {
			writeJobError(w, operations.ErrNotFound)
			return
		}
		release := lockCalendarAccess(d, mu)
		defer release()
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "exec"}
		check := p
		check.AccessOrigin = origin
		if !authorizeOperationOwner(d, check, authorize, false) {
			writeJobError(w, operations.ErrDenied)
			return
		}
		out, e := d.Operations.TriggerPlan(p.ID, in.RequestID, operations.ScheduleActor{ID: user.ID, Name: user.Username}, origin)
		if e != nil {
			writePlaybookError(w, e)
			return
		}
		writeJSON(w, 201, operations.PublicRun(out))
	}))
}
