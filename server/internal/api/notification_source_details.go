package api

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/notifications"
	"time"
)

// This DTO deliberately excludes login permits, execution output, native
// plugin payloads, credential bindings and raw agent collection receipts.
type notificationSourceDetail struct {
	ReviewID  string    `json:"review_id,omitempty"`
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	AssetID   string    `json:"asset_id,omitempty"`
	Account   string    `json:"account,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Command   string    `json:"command,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Method    string    `json:"method,omitempty"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	CanReview bool      `json:"can_review"`
	Accounts  int       `json:"accounts,omitempty"`
	Open      int       `json:"open,omitempty"`
	Resolved  int       `json:"resolved,omitempty"`
}

func notificationSourceDetails(ctx context.Context, d Dependencies, user, kind, id string) (notificationSourceDetail, error) {
	out := notificationSourceDetail{ID: id, Kind: kind}
	u, p, ok := notificationActor(ctx, d, user)
	if !ok {
		return out, notifications.ErrDenied
	}
	switch kind {
	case "access-reviews":
		if d.AccessReviews == nil {
			return out, notifications.ErrNotFound
		}
		r, e := d.AccessReviews.Get(id)
		if errors.Is(e, accessreviews.ErrNotFound) {
			return out, notifications.ErrNotFound
		}
		if e != nil {
			return out, e
		}
		if r.UserID != user && !p.Allows("reviews.login.manage") {
			return out, notifications.ErrNotFound
		}
		out.Name, out.State, out.AssetID, out.Account, out.Owner, out.Method, out.At, out.ExpiresAt = r.AssetName, r.State, r.AssetID, r.Account, r.Operator, r.Action, r.RequestedAt, r.ExpiresAt
		out.CanReview = p.Allows("reviews.login.manage") && r.State == accessreviews.StatePending
	case "job-security":
		if d.Jobs == nil {
			return out, notifications.ErrNotFound
		}
		meta, e := d.Jobs.SecurityNotificationInfo(id)
		if errors.Is(e, jobs.ErrNotFound) {
			return out, notifications.ErrNotFound
		}
		if e != nil {
			return out, e
		}
		if meta.OwnerID != user && !p.Allows("jobs.view_all") && !(p.Allows("jobs.review") && meta.State == "pending_review") {
			return out, notifications.ErrNotFound
		}
		j, e := d.Jobs.Get(id)
		if e != nil {
			return out, notifications.ErrNotFound
		}
		// Recheck the state after the metadata read: a delegated reviewer cannot
		// obtain another user's terminal history through a pending-review link.
		if j.OperatorID != user && !p.Allows("jobs.view_all") && !(p.Allows("jobs.review") && j.State == "pending_review") {
			return out, notifications.ErrNotFound
		}
		out.Name, out.State, out.AssetID, out.Account, out.Owner, out.Command, out.Rule, out.At = j.AssetName, j.State, j.AssetID, j.Account, j.Operator, j.Command, j.RuleName, j.CreatedAt
		out.CanReview = p.Allows("jobs.review") && j.State == "pending_review"
		if j.State == "pending_review" {
			out.ExpiresAt = j.CreatedAt.Add(5 * time.Minute)
		}
	case "command-reviews":
		if d.Sessions == nil || !p.Allows("reviews.command.manage") {
			return out, notifications.ErrNotFound
		}
		found := false
		for _, r := range d.Sessions.ListPendingCommandReviews() {
			if "command-review-"+r.ID == id {
				out.ReviewID = r.ID
				out.Name, out.State, out.AssetID, out.Account, out.Owner, out.Command, out.Rule, out.At, out.ExpiresAt = r.AssetName, "pending", r.AssetID, r.Account, r.Operator, r.Command, r.RuleName, r.RequestedAt, r.ExpiresAt
				if r.Actor != "" {
					out.Owner = r.Actor
				}
				out.CanReview = true
				found = true
				break
			}
		}
		if !found {
			return out, notifications.ErrNotFound
		}
	case "command-alerts":
		if d.CommandAlerts == nil {
			return out, notifications.ErrNotFound
		}
		r, err := d.CommandAlerts.Get(id)
		if errors.Is(err, commandalerts.ErrNotFound) {
			return out, notifications.ErrNotFound
		}
		if err != nil {
			return out, err
		}
		if user != r.OwnerID && user != r.ActorID && !p.Allows("audit.commands.view_all") {
			return out, notifications.ErrNotFound
		}
		out.Name, out.State, out.AssetID, out.Account, out.Owner, out.Rule, out.At = r.AssetName, r.State, r.AssetID, r.Account, r.Actor, r.Rule, r.At
	case "agent-events":
		if d.AgentEvents == nil {
			return out, notifications.ErrNotFound
		}
		r, e := d.AgentEvents.NotificationSource(id)
		if errors.Is(e, agentevents.ErrNotificationNotFound) {
			return out, notifications.ErrNotFound
		}
		if e != nil {
			return out, e
		}
		if r.State == "" || !agentSourceAllowed(d, u, r.Source) {
			return out, notifications.ErrNotFound
		}
		out.Name, out.State, out.AssetID, out.Account, out.Owner, out.At = r.AssetName, r.State, r.AssetID, r.Account, r.CollectorID, r.ObservedAt
	case "account-risks":
		if d.AccountRisks == nil || !p.Allows("accounts.risks.view") || !p.Allows("assets.view_all") && !p.Allows("assets.manage") {
			return out, notifications.ErrNotFound
		}
		r, ok := d.AccountRisks.ScanRecord(id)
		if !ok {
			return out, notifications.ErrNotFound
		}
		out.State, out.Owner, out.At, out.Accounts, out.Open, out.Resolved = r.State, r.Actor.Name, r.FinishedAt, r.Accounts, r.Open, r.Resolved
		if out.At.IsZero() {
			out.At = r.StartedAt
		}
	default:
		return out, notifications.ErrNotFound
	}
	return out, nil
}
