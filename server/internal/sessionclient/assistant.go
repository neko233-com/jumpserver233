package sessionclient

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/assistant"
)

type AssistantSettingsInput = assistant.SettingsInput
type AssistantSettings = assistant.SettingsView
type AssistantInput = assistant.Input
type AssistantResult = assistant.SubmitResult
type AssistantConversation = assistant.Conversation
type AssistantPage = assistant.Page
type AssistantAuditPage = assistant.AuditPage

func (c *Client) AssistantSettings(ctx context.Context) (AssistantSettings, error) {
	var out AssistantSettings
	e := c.jobRequest(ctx, "GET", "/api/v1/assistant/settings", nil, &out)
	return out, e
}
func (c *Client) SaveAssistantSettings(ctx context.Context, in AssistantSettingsInput) (AssistantSettings, error) {
	var out AssistantSettings
	e := c.jobRequest(ctx, "PUT", "/api/v1/assistant/settings", in, &out)
	return out, e
}
func (c *Client) AskAssistant(ctx context.Context, in AssistantInput) (AssistantResult, error) {
	var out AssistantResult
	e := c.jobRequest(ctx, "POST", "/api/v1/assistant/turns", in, &out)
	return out, e
}
func (c *Client) AssistantConversations(ctx context.Context, all, archived bool, offset, limit int) (AssistantPage, error) {
	var out AssistantPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, assistant.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/assistant/conversations?all=%t&archived=%t&offset=%d&limit=%d", all, archived, offset, limit), nil, &out)
	return out, e
}
func (c *Client) AssistantConversation(ctx context.Context, id string, all bool) (AssistantConversation, error) {
	var out AssistantConversation
	if !validAssistantConversation(id) {
		return out, assistant.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/assistant/conversations/%s?all=%t", id, all), nil, &out)
	return out, e
}
func (c *Client) ArchiveAssistantConversation(ctx context.Context, id string, revision int, request string) error {
	if !validAssistantConversation(id) {
		return assistant.ErrInvalid
	}
	return c.jobRequest(ctx, "POST", "/api/v1/assistant/conversations/"+id+"/archive", struct {
		Revision  int    `json:"revision"`
		RequestID string `json:"request_id"`
	}{revision, request}, nil)
}
func (c *Client) AssistantAudit(ctx context.Context, offset, limit int) (AssistantAuditPage, error) {
	var out AssistantAuditPage
	if offset < 0 || limit < 1 || limit > 100 {
		return out, assistant.ErrInvalid
	}
	e := c.jobRequest(ctx, "GET", fmt.Sprintf("/api/v1/assistant/audit?offset=%d&limit=%d", offset, limit), nil, &out)
	return out, e
}
func validAssistantConversation(id string) bool {
	if len(id) != 37 || id[:5] != "chat-" {
		return false
	}
	for _, r := range id[5:] {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
