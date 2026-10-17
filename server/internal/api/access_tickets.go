package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/core/tickets"
)

func ticketError(w http.ResponseWriter, e error) {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, tickets.ErrInvalid):
		status, code = 400, "invalid"
	case errors.Is(e, tickets.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(e, tickets.ErrDenied):
		status, code = 403, "denied"
	case errors.Is(e, tickets.ErrConflict), errors.Is(e, grants.ErrTicketConflict):
		status, code = 409, "conflict"
	case errors.Is(e, tickets.ErrStale):
		status, code = 409, "source_changed"
	case errors.Is(e, tickets.ErrReviewers):
		status, code = 409, "reviewers_unavailable"
	case errors.Is(e, tickets.ErrCapacity), errors.Is(e, grants.ErrTicketCapacity):
		status, code = 429, "capacity"
	}
	writeJSON(w, status, map[string]string{"error_code": code})
}
func ticketPrincipal(ctx context.Context, d Dependencies, id string) (tickets.Principal, error) {
	if e := ctx.Err(); e != nil {
		return tickets.Principal{}, e
	}
	u, ok := jobOwner(d, id)
	if !ok || d.OrganizationAllowed != nil && !d.OrganizationAllowed(u) {
		return tickets.Principal{}, tickets.ErrDenied
	}
	perms := effectivePermissions(u, d.RBAC, d.Groups)
	p := tickets.Principal{Actor: tickets.Actor{ID: u.ID, Name: u.Username}, CanPublish: perms.Allows("tickets.manage") && perms.Allows("grants.manage") && perms.Allows("assets.view_all"), CanReview: perms.Allows("tickets.review"), CanViewAll: perms.Allows("tickets.view_all"), CanRevoke: perms.Allows("tickets.revoke")}
	for _, role := range perms.RoleIDs {
		p.Subjects = append(p.Subjects, tickets.Subject{Kind: "role", ID: role})
	}
	if d.Groups != nil {
		for _, group := range d.Groups.GroupIDsForUser(id) {
			p.Subjects = append(p.Subjects, tickets.Subject{Kind: "group", ID: group})
		}
	}
	return p, nil
}

func registerTicketRoutes(mux *http.ServeMux, d Dependencies, accessMu *sync.RWMutex) {
	if d.Tickets == nil || d.Assets == nil || d.Auth == nil || d.Grants == nil {
		return
	}
	service := d.Tickets
	tree := func() []nodes.Node {
		if d.Nodes == nil {
			return nil
		}
		return d.Nodes.List()
	}
	people := func(ctx context.Context) ([]tickets.Principal, error) {
		out := []tickets.Principal{}
		for _, u := range d.Auth.ListUsers() {
			p, e := ticketPrincipal(ctx, d, u.ID)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if e == nil {
				out = append(out, p)
			}
		}
		return out, nil
	}
	// Context-aware locks let organization shutdown stop a queued recovery step.
	lock := func(ctx context.Context) (func(), error) {
		global := d.GlobalAccessMu
		lockedGlobal := false
		timer := time.NewTicker(5 * time.Millisecond)
		defer timer.Stop()
		for {
			if e := ctx.Err(); e != nil {
				if lockedGlobal {
					global.RUnlock()
				}
				return nil, e
			}
			if global != nil && global != accessMu && !lockedGlobal {
				lockedGlobal = global.TryRLock()
				if !lockedGlobal {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-timer.C:
					}
					continue
				}
			}
			if accessMu.TryLock() {
				return func() {
					accessMu.Unlock()
					if lockedGlobal {
						global.RUnlock()
					}
				}, nil
			}
			select {
			case <-ctx.Done():
				if lockedGlobal {
					global.RUnlock()
				}
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	service.SetRunner(tickets.Runner{
		Principal: func(ctx context.Context, id string) (tickets.Principal, error) { return ticketPrincipal(ctx, d, id) }, People: people,
		ValidatePolicy: func(ctx context.Context, in tickets.PolicyInput) error {
			subjects := append(append([]tickets.Subject{}, in.Requesters...), in.CC...)
			for _, stage := range in.Stages {
				subjects = append(subjects, stage.Subjects...)
			}
			for _, v := range subjects {
				found := false
				switch v.Kind {
				case "user":
					_, e := ticketPrincipal(ctx, d, v.ID)
					found = e == nil
				case "group":
					if d.Groups != nil {
						_, e := d.Groups.Get(v.ID)
						found = e == nil
					}
				case "role":
					if d.RBAC != nil {
						for _, role := range d.RBAC.Roles() {
							if role.ID == v.ID {
								found = true
							}
						}
						if !found {
							peers, e := people(ctx)
							if e != nil {
								return e
							}
							for _, p := range peers {
								for _, sub := range p.Subjects {
									if sub == v {
										found = true
									}
								}
							}
						}
					}
				}
				if !found {
					return tickets.ErrInvalid
				}
			}
			for _, scope := range in.Scopes {
				for _, account := range scope.Accounts {
					if _, e := d.Assets.ResolveAccessTargets(ctx, []tickets.Target{{Kind: scope.Kind, ID: scope.ID, Account: account, Actions: scope.Actions}}, tree()); e != nil {
						return tickets.ErrInvalid
					}
				}
			}
			return nil
		},
		Resolve: func(ctx context.Context, targets []tickets.Target) ([]tickets.Prepared, error) {
			return d.Assets.ResolveAccessTargets(ctx, targets, tree())
		},
		Catalog: func(ctx context.Context, p tickets.Policy, q string, offset, limit int) (tickets.Page[tickets.Ref], error) {
			return d.Assets.AccessCatalog(ctx, p, tree(), q, offset, limit)
		},
		Receipt: d.Grants.TicketReceipt,
		Prune:   d.Grants.PruneTicketReceipts,
		Issue: func(ctx context.Context, in tickets.Intent, guard func() error, commit func(grants.TicketReceipt) error) (grants.TicketReceipt, error) {
			release, e := lock(ctx)
			if e != nil {
				return grants.TicketReceipt{}, e
			}
			defer release()
			if e = guard(); e != nil {
				return grants.TicketReceipt{}, e
			}
			inputs := make([]grants.Input, 0, len(in.Targets))
			for _, v := range in.Targets {
				row := grants.Input{UserID: in.Owner.ID, Account: v.Account, Actions: v.Actions, StartsAt: &in.StartsAt, EndsAt: &in.EndsAt}
				if v.Kind == "asset" {
					row.AssetID = v.ID
				} else {
					row.NodeID = v.ID
				}
				inputs = append(inputs, row)
			}
			receipt, e := d.Grants.IssueTicket(in.TicketID, in.Digest, inputs, in.Publisher.ID)
			if e != nil {
				return receipt, e
			}
			if e = guard(); e == nil {
				e = commit(receipt)
			}
			return receipt, e
		},
		Revoke: func(ctx context.Context, in tickets.Intent) (grants.TicketReceipt, error) {
			release, e := lock(ctx)
			if e != nil {
				return grants.TicketReceipt{}, e
			}
			defer release()
			return d.Grants.RevokeTicket(in.TicketID, in.Digest, in.EndsAt)
		},
	})
	d.Grants.SetTicketGuard(service.GrantGuard)
	protect := func(h http.HandlerFunc) http.Handler { return protectAuthenticatedAPI(h, d.AdminToken, d.Auth) }
	actor := func(w http.ResponseWriter, r *http.Request) (tickets.Principal, bool) {
		setNoStore(w)
		u, ok := PrincipalFromContext(r.Context())
		if !ok {
			ticketError(w, tickets.ErrDenied)
			return tickets.Principal{}, false
		}
		p, e := ticketPrincipal(r.Context(), d, u.ID)
		if e != nil {
			ticketError(w, e)
			return p, false
		}
		return p, true
	}
	decode := func(w http.ResponseWriter, r *http.Request, out any) bool {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
			ticketError(w, tickets.ErrInvalid)
			return false
		}
		return true
	}
	paging := func(w http.ResponseWriter, r *http.Request) (int, int, bool) {
		offset, e := strconv.Atoi(defaultQuery(r, "offset", "0"))
		limit, e2 := strconv.Atoi(defaultQuery(r, "limit", "25"))
		if e != nil || e2 != nil || offset < 0 || limit < 1 || limit > 100 {
			ticketError(w, tickets.ErrInvalid)
			return 0, 0, false
		}
		return offset, limit, true
	}
	respond := func(w http.ResponseWriter, out any, e error) {
		if e != nil {
			ticketError(w, e)
		} else {
			writeJSON(w, 200, out)
		}
	}
	const base = "/api/v1/tickets"
	mux.Handle("GET "+base+"/resources", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		if !p.CanPublish {
			ticketError(w, tickets.ErrDenied)
			return
		}
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		q := strings.ToLower(r.URL.Query().Get("search"))
		if len(q) > 240 {
			ticketError(w, tickets.ErrInvalid)
			return
		}
		type resource struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Kind     string   `json:"kind"`
			Accounts []string `json:"accounts"`
		}
		rows := []resource{}
		choices := d.Assets.AccountChoices()
		for _, a := range d.Assets.List() {
			if q != "" && !strings.Contains(strings.ToLower(a.Name+" "+a.ID), q) {
				continue
			}
			accounts := []string{}
			if assets.IsSSH(a.Asset) {
				for _, v := range choices[a.ID] {
					if v.Active {
						accounts = append(accounts, v.Username)
					}
				}
			} else if !a.AccountDisabled {
				accounts = append(accounts, a.Username)
			}
			if len(accounts) > 0 {
				rows = append(rows, resource{a.ID, a.Name, "asset", accounts})
			}
		}
		for _, n := range tree() {
			if q == "" || strings.Contains(strings.ToLower(n.Name+" "+n.ID), q) {
				rows = append(rows, resource{n.ID, n.Name, "node", []string{}})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name+rows[i].ID < rows[j].Name+rows[j].ID })
		total := len(rows)
		offset = min(offset, total)
		writeJSON(w, 200, tickets.Page[resource]{Results: rows[offset:min(total, offset+limit)], Total: total})
	}))
	mux.Handle("GET "+base+"/capabilities", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if ok {
			writeJSON(w, 200, map[string]bool{"publish": p.CanPublish, "review": p.CanReview, "view_all": p.CanViewAll, "revoke": p.CanRevoke})
		}
	}))
	mux.Handle("GET "+base+"/choices", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		if !p.CanPublish {
			ticketError(w, tickets.ErrDenied)
			return
		}
		peers, e := people(r.Context())
		if e != nil {
			ticketError(w, e)
			return
		}
		type choice struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		rows := []choice{}
		roles := map[string]bool{}
		for _, p := range peers {
			rows = append(rows, choice{"user", p.ID, p.Name})
			for _, sub := range p.Subjects {
				if sub.Kind == "role" {
					roles[sub.ID] = true
				}
			}
		}
		if d.Groups != nil {
			for _, g := range d.Groups.List() {
				rows = append(rows, choice{"group", g.ID, g.Name})
			}
		}
		if d.RBAC != nil {
			for _, role := range d.RBAC.Roles() {
				rows = append(rows, choice{"role", role.ID, role.Name})
				delete(roles, role.ID)
			}
		}
		for id := range roles {
			rows = append(rows, choice{"role", id, id})
		}
		writeJSON(w, 200, map[string]any{"subjects": rows})
	}))
	mux.Handle("GET "+base+"/policies", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		out, e := service.Policies(r.Context(), p.ID, offset, limit)
		respond(w, out, e)
	}))
	save := func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in tickets.PolicyInput
		if !decode(w, r, &in) {
			return
		}
		out, e := service.SavePolicy(r.Context(), p.ID, r.PathValue("id"), in)
		respond(w, out, e)
	}
	mux.Handle("POST "+base+"/policies", protect(save))
	mux.Handle("PUT "+base+"/policies/{id}", protect(save))
	mux.Handle("GET "+base+"/policies/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		out, e := service.Policy(r.Context(), p.ID, r.PathValue("id"))
		respond(w, out, e)
	}))
	mux.Handle("DELETE "+base+"/policies/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in struct {
			Revision int `json:"revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		e := service.DeletePolicy(r.Context(), p.ID, r.PathValue("id"), in.Revision)
		respond(w, map[string]bool{"deleted": e == nil}, e)
	}))
	mux.Handle("GET "+base+"/policies/{id}/catalog", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		out, e := service.Catalog(r.Context(), p.ID, r.PathValue("id"), r.URL.Query().Get("search"), offset, limit)
		respond(w, out, e)
	}))
	mux.Handle("GET "+base+"/requests", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		out, e := service.List(r.Context(), p.ID, tickets.Query{View: defaultQuery(r, "view", "mine"), State: r.URL.Query().Get("state"), Search: r.URL.Query().Get("search"), Offset: offset, Limit: limit})
		respond(w, out, e)
	}))
	mux.Handle("POST "+base+"/requests", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in tickets.SubmitInput
		if !decode(w, r, &in) {
			return
		}
		out, e := service.Submit(r.Context(), p.ID, in)
		respond(w, out, e)
	}))
	mux.Handle("GET "+base+"/requests/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		out, e := service.Get(r.Context(), p.ID, r.PathValue("id"))
		respond(w, out, e)
	}))
	mux.Handle("PUT "+base+"/requests/{id}", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in tickets.Amendment
		if !decode(w, r, &in) {
			return
		}
		out, e := service.Amend(r.Context(), p.ID, r.PathValue("id"), in)
		respond(w, out, e)
	}))
	mux.Handle("POST "+base+"/requests/{id}/decisions", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in tickets.Decision
		if !decode(w, r, &in) {
			return
		}
		out, e := service.Decide(r.Context(), p.ID, r.PathValue("id"), in)
		respond(w, out, e)
	}))
	mux.Handle("POST "+base+"/requests/{id}/comments", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in struct {
			Text string `json:"text"`
		}
		if !decode(w, r, &in) {
			return
		}
		out, e := service.Comment(r.Context(), p.ID, r.PathValue("id"), in.Text)
		respond(w, out, e)
	}))
	mux.Handle("POST "+base+"/requests/{id}/cancel", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		var in struct {
			Revision int `json:"revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		out, e := service.Cancel(r.Context(), p.ID, r.PathValue("id"), in.Revision)
		respond(w, out, e)
	}))
	mux.Handle("GET "+base+"/audit", protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := actor(w, r)
		if !ok {
			return
		}
		offset, limit, ok := paging(w, r)
		if !ok {
			return
		}
		out, e := service.Audit(r.Context(), p.ID, offset, limit)
		respond(w, out, e)
	}))
}
