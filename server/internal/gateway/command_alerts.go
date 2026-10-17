package gateway

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/commandalerts"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
)

// Setter shares the audit lock so a running command has one stable publisher.
// Publication completes after full audit fsync and before terminal forwarding.
func (b *Broker) SetCommandAlerts(publish func(commandalerts.Record) error) {
	b.commandAuditMu.Lock()
	defer b.commandAuditMu.Unlock()
	b.commandAlert = publish
}
func commandAlertState(s commandSubmission) string {
	switch s.Outcome {
	case "blocked":
		if s.Supported && s.Command != "" {
			return "command_denied"
		}
		return "command_input_blocked"
	case "pending":
		return "command_review_pending"
	case "approved":
		return "command_review_approved"
	case "denied":
		if s.ReviewID != "" {
			return "command_review_denied"
		}
		return "command_denied"
	case "timed_out":
		return "command_review_expired"
	case "cancelled":
		return "command_review_cancelled"
	}
	return ""
}
func commandAlertRecord(s *activeSession, in commandSubmission, id string) commandalerts.Record {
	actorID, actor := in.ActorID, in.Actor
	if actorID == "" {
		actorID = s.operatorID
	}
	if actor == "" {
		actor = s.operator
	}
	return commandalerts.Record{ID: "command-event-" + id, SessionID: s.id, ReviewID: in.ReviewID, AssetID: s.asset.ID, AssetName: eventfeed.MetadataText(s.asset.Name, 480), Account: eventfeed.MetadataText(s.asset.Username, 128), OwnerID: s.operatorID, ActorID: actorID, Actor: eventfeed.MetadataText(actor, 128), State: commandAlertState(in), Rule: eventfeed.MetadataText(in.RuleName, 80), At: in.SubmittedAt.UTC()}
}
