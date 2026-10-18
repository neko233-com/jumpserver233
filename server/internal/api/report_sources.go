package api

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountrisks"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/monitoralerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"slices"
	"time"
)

func reportSources(ctx context.Context, d Dependencies, u coreauth.User, p rbac.Snapshot, query reporting.Query) []reporting.Source {
	wants := func(id string) bool { return len(query.Sources) == 0 || slices.Contains(query.Sources, id) }
	allAssets := p.Allows("assets.view_all") || p.Allows("assets.manage")
	assetScope := "visible"
	if allAssets {
		assetScope = "all"
	}
	allowedAssets, allowedAccounts := map[string]bool{}, map[string]bool{}
	var groups []string
	if d.Groups != nil {
		groups = d.Groups.GroupIDsForUser(u.ID)
	}
	var inventory []assets.ListItem
	var choices map[string][]assets.AccountChoice
	var versions map[string]string
	if wants("assets") || wants("accounts") || wants("account_risks") || wants("monitor_alerts") {
		inventory = d.Assets.List()
		choices = d.Assets.AccountChoices()
	}
	if wants("account_risks") {
		versions = d.Assets.AccountRiskVersions()
	}
	for _, a := range inventory {
		var nodes []string
		if d.Nodes != nil {
			nodes = d.Nodes.AncestorIDs(a.NodeID)
		}
		allowedAssets[a.ID] = allAssets || hasAction(scopedAssetActions(u.ID, a.Asset, p, d.Grants, groups, nodes), "view")
		rows := choices[a.ID]
		if !allAssets {
			rows = visibleAccountChoices(u.ID, a.ID, rows, p, d.Grants, groups, nodes)
		}
		if len(rows) > 0 {
			allowedAssets[a.ID] = true
		}
		for _, c := range rows {
			allowedAccounts[c.ID] = true
		}
	}
	out := []reporting.Source{}
	add := func(id, scope, mode string, available, allowed bool, read func(context.Context, func(reporting.Entry) error) error) {
		s := reporting.Source{ID: id, Scope: scope, Mode: mode, Read: read}
		if !allowed {
			s.Status = "denied"
		} else if !available {
			s.Status = "unavailable"
		}
		out = append(out, s)
	}
	observations := map[string]monitoralerts.Source{}
	if wants("assets") {
		for _, v := range d.Assets.MonitorSources(func(string) []string { return nil }) {
			observations[v.AssetID] = v
		}
	}
	add("assets", assetScope, "inventory", true, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		for _, a := range inventory {
			if !allowedAssets[a.ID] {
				continue
			}
			state := "not_monitored"
			if assets.IsSSH(a.Asset) {
				state = "unknown"
				if v, ok := observations[a.ID]; ok {
					state = v.State
					if !v.At.IsZero() && time.Since(v.At) > 3*time.Minute {
						state = "stale"
					}
				}
			}
			if e := emit(reporting.Entry{At: a.CreatedAt, State: state}); e != nil {
				return e
			}
		}
		return nil
	})
	add("accounts", assetScope, "inventory", true, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		for _, rows := range choices {
			for _, c := range rows {
				if !allowedAccounts[c.ID] {
					continue
				}
				state := "inactive"
				if c.Active {
					state = "active"
				}
				if e := emit(reporting.Entry{State: state}); e != nil {
					return e
				}
			}
		}
		return nil
	})
	scope := func(all bool) string {
		if all {
			return "all"
		}
		return "mine"
	}
	all := p.Allows("audit.sessions.view_all") || p.Allows("audit.sessions.monitor_all")
	add("terminal_sessions", scope(all), "history", d.Sessions != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.Sessions.ReportMetadata(ctx, u.ID, all, emit)
	})
	rdpAll := p.Allows("audit.sessions.view_all") || p.Allows("audit.desktops.monitor_all")
	add("rdp_sessions", scope(rdpAll), "history", d.Desktops != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.Desktops.ReportMetadata(ctx, u.ID, rdpAll, emit)
	})
	dbAll := p.Allows("database.audit.view_all")
	add("database_queries", scope(dbAll), "history", d.DatabaseQueries != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.DatabaseQueries.ReportMetadata(ctx, u.ID, dbAll, emit)
	})
	jobsAll := p.Allows("jobs.view_all")
	add("ssh_jobs", scope(jobsAll), "history", d.Jobs != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.Jobs.ReportMetadata(ctx, u.ID, jobsAll, emit)
	})
	add("rotation_runs", "all", "history", d.RotationPlans != nil, p.Allows("accounts.rotation.view") && p.Allows("assets.view_all"), func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.RotationPlans.ReportMetadata(ctx, emit)
	})
	add("account_risks", assetScope, "history", d.AccountRisks != nil, p.Allows("accounts.risks.view"), func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.AccountRisks.ReportMetadata(ctx, func(v accountrisks.Ref) bool { return allAssets || allowedAccounts[v.AccountID] }, func(v accountrisks.Finding) bool { return versions[v.AccountID] == v.SourceVersion }, emit)
	})
	add("monitor_alerts", assetScope, "history", d.MonitorAlerts != nil, p.Allows("monitoring.view") || p.Allows("monitoring.manage"), func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.MonitorAlerts.ReportMetadata(ctx, func(v monitoralerts.Alert) bool { return allAssets || allowedAssets[v.AssetID] }, emit)
	})
	ticketScope := "visible"
	if p.Allows("tickets.view_all") {
		ticketScope = "all"
	}
	add("access_tickets", ticketScope, "history", d.Tickets != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.Tickets.ReportMetadata(ctx, u.ID, emit)
	})
	agentAll := p.Allows("audit.agents.view_all")
	agentScope := "visible"
	if agentAll {
		agentScope = "all"
	}
	type agentKey struct{ asset, account string }
	agentVisibility := map[agentKey]bool{}
	add("agent_alerts", agentScope, "history", d.AgentEvents != nil, agentAll || p.Allows("plugins.inspect") || p.Allows("plugins.manage") || p.Allows("plugins.protect"), func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.AgentEvents.ReportMetadata(ctx, func(v agentevents.Source) bool {
			key := agentKey{v.AssetID, v.Account}
			if allowed, exists := agentVisibility[key]; exists {
				return allowed
			}
			allowed := agentSourceAllowed(d, u, v)
			agentVisibility[key] = allowed
			return allowed
		}, emit)
	})
	fileAll := p.Allows("audit.files.view_all")
	add("file_transfers", scope(fileAll), "history", d.Files != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
		return d.Files.ReportMetadata(ctx, u.Username, fileAll, emit)
	})
	if query.IncludePlatform {
		global := globalLoginPermissions(d, u)
		loginAll := global.Allows("audit.logins.view_all")
		loginScope := "platform_mine"
		if loginAll {
			loginScope = "platform_all"
		}
		add("platform_logins", loginScope, "history", d.LoginAudit != nil, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
			return d.LoginAudit.ReportMetadata(ctx, u.ID, loginAll, emit)
		})
		userAll := global.Allows("users.manage")
		userScope := "platform_mine"
		if userAll {
			userScope = "platform_all"
		}
		add("platform_users", userScope, "inventory", true, true, func(ctx context.Context, emit func(reporting.Entry) error) error {
			users := []coreauth.User{u}
			if userAll {
				users = d.Auth.ListUsers()
			}
			active := map[string]bool{}
			for _, v := range d.Auth.ActiveUsersSnapshot() {
				active[v.ID] = true
			}
			for _, v := range users {
				state := "external_disabled"
				if active[v.ID] {
					state = "active"
				}
				if e := emit(reporting.Entry{At: v.CreatedAt, State: state}); e != nil {
					return e
				}
			}
			return nil
		})
	}
	return out
}
