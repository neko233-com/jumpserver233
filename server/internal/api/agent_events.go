package api

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func configureAgentCollection(d Dependencies, mu *sync.RWMutex) {
	if d.AgentEvents == nil || d.Operations == nil {
		return
	}
	d.Operations.SetCollectorHooks(func(in jobs.Input) (jobs.Input, error) {
		mu.RLock()
		defer mu.RUnlock()
		if in.Plugin == nil || in.Plugin.Action != "events_collect" {
			return in, jobs.ErrInvalid
		}
		a, e := d.Assets.Get(in.AssetID)
		if e != nil {
			return in, e
		}
		op := in.Plugin.Clone()
		op.Binding = databaseRouteBinding(d, a)
		in.Plugin = &op
		in.Command = op.Command()
		return in, nil
	}, func(r operations.Run, j *jobs.Job) error {
		src := agentevents.Source{AssetID: r.Items[0].AssetID, AssetName: r.CollectionAssetName, Account: r.CollectionAccount}
		col := agentevents.Collector{ID: r.OwnerID}
		var jobJSON []byte
		if j != nil {
			src = agentevents.Source{AssetID: j.AssetID, AssetName: j.AssetName, Account: j.Account}
			col.Name = j.Operator
			col.JobID = j.ID
			jobJSON, _ = json.Marshal(j)
		}
		runJSON, _ := json.Marshal(r)
		return d.AgentEvents.Archive(src, col, agentevents.Receipt{PlanID: r.PlanID, Sequence: r.CollectionSequence, RunID: r.ID, JobID: r.Items[0].JobID, OwnerID: r.OwnerID, State: r.State, Run: runJSON, Job: jobJSON})
	})
}
func agentSourceAllowed(d Dependencies, u coreauth.User, src agentevents.Source) bool {
	p := effectivePermissions(u, d.RBAC, d.Groups)
	if p.Allows("audit.agents.view_all") {
		return true
	}
	if !p.Allows("plugins.inspect") && !p.Allows("plugins.manage") && !p.Allows("plugins.protect") {
		return false
	}
	a, e := d.Assets.Get(src.AssetID)
	if e != nil || a.Username != src.Account || !assets.IsSSH(a) {
		return false
	}
	if p.Allows("assets.connect_all") {
		return true
	}
	var groups, nodes []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	if d.Nodes != nil {
		nodes = d.Nodes.AncestorIDs(a.NodeID)
	}
	return d.Grants != nil && d.Grants.AllowsForScopes(u.ID, groups, a.ID, nodes, a.Username, "connect", time.Now().UTC())
}
func registerAgentEventRoutes(mux *http.ServeMux, d Dependencies, authorize func(coreauth.User, string, string, accesspolicies.Origin) (string, string, commandfilters.Decision, int), mu *sync.RWMutex) {
	if d.AgentEvents == nil {
		return
	}
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	list := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		mu.RLock()
		defer mu.RUnlock()
		global := r.PathValue("assetID") == ""
		if global && !hasPermission(r, "audit.agents.view_all") {
			writeJSON(w, 403, map[string]string{"detail": "agent audit permission required"})
			return
		}
		before, e := strconv.ParseUint(defaultQuery(r, "before", "0"), 10, 64)
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "50"))
		if e != nil || e2 != nil || limit < 1 || limit > 100 {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		kind := defaultQuery(r, "kind", "all")
		if kind != "all" && kind != "host" && kind != "collection" {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		assetID := r.PathValue("assetID")
		if !global {
			a, e := d.Assets.Get(assetID)
			if e != nil || !agentSourceAllowed(d, u, agentevents.Source{AssetID: a.ID, Account: a.Username}) {
				writeJobError(w, jobs.ErrNotFound)
				return
			}
		}
		page, e := d.AgentEvents.List(before, limit, func(src agentevents.Source) bool {
			return (global || src.AssetID == assetID) && agentSourceAllowed(d, u, src)
		}, kind)
		if e != nil {
			writeJSON(w, 503, map[string]string{"detail": "agent audit unavailable"})
			return
		}
		writeJSON(w, 200, page)
	}
	mux.Handle("GET /api/v1/audit/agent-events", protect(list))
	mux.Handle("GET /api/v1/assets/{assetID}/agent-events", protect(list))
	collection := func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		u, _ := PrincipalFromContext(r.Context())
		mu.RLock()
		defer mu.RUnlock()
		a, e := d.Assets.Get(r.PathValue("assetID"))
		if e != nil || !agentSourceAllowed(d, u, agentevents.Source{AssetID: a.ID, Account: a.Username}) {
			writeJobError(w, jobs.ErrNotFound)
			return
		}
		plans := []operations.Plan{}
		for _, p := range d.Operations.Plans(u.ID) {
			if p.HostPlugin != nil && len(p.AssetIDs) == 1 && p.AssetIDs[0] == a.ID {
				plans = append(plans, p)
			}
		}
		if r.Method == http.MethodGet {
			writeJSON(w, 200, plans)
			return
		}
		if !hasPermission(r, "plugins.manage") {
			writeJobError(w, operations.ErrDenied)
			return
		}
		var in struct {
			Enabled   *bool  `json:"enabled"`
			Interval  int    `json:"interval_seconds"`
			RequestID string `json:"request_id"`
		}
		if decodeRequestJSON(w, r, &in) != nil || in.Enabled == nil || in.RequestID == "" {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		if in.Interval == 0 {
			in.Interval = 300
		}
		if in.Interval < 60 || in.Interval > 86400 {
			writeJobError(w, jobs.ErrInvalid)
			return
		}
		if !*in.Enabled {
			for _, p := range plans {
				if p.Enabled {
					if e = d.Operations.SetEnabled(p.ID, false); e != nil {
						writeJobError(w, e)
						return
					}
				}
			}
			writeJSON(w, 200, map[string]bool{"enabled": false})
			return
		}
		def, _ := hostplugins.Lookup("banhack233")
		op := hostplugins.Operation{Plugin: def.ID, Action: "events_collect", Version: def.Version, Selection: "installed", Binding: databaseRouteBinding(d, a)}
		origin := accesspolicies.Origin{SourceIP: accesspolicies.SourceIP(r.Context()), Method: "scheduled_exec"}
		_, _, decision, status := authorize(u, a.ID, op.Command(), origin)
		if status != 200 || decision.Action == commandfilters.ActionDeny {
			writeJobError(w, operations.ErrDenied)
			return
		}
		for _, p := range plans {
			if p.Enabled {
				if p.IntervalSeconds != in.Interval {
					writeJobError(w, jobs.ErrConflict)
					return
				}
				writeJSON(w, 200, p)
				return
			}
		}
		p, e := d.Operations.CreateCollector(u.ID, u.Username, operations.PlanInput{Name: "banhack233 agent events", AssetIDs: []string{a.ID}, Kind: "interval", IntervalSeconds: in.Interval, RequestID: in.RequestID, Origin: origin}, op, a.Username, a.Name)
		if e != nil {
			writeJobError(w, e)
			return
		}
		writeJSON(w, 201, p)
	}
	mux.Handle("GET /api/v1/assets/{assetID}/agent-events/collection", protect(collection))
	mux.Handle("POST /api/v1/assets/{assetID}/agent-events/collection", protect(collection))
}
