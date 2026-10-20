// Package assistant owns organization-scoped advisory conversations and audit.
package assistant

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/aichat"
	"regexp"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid assistant request")
	ErrDenied   = errors.New("assistant access denied")
	ErrConflict = errors.New("assistant revision or request conflict")
	ErrNotFound = errors.New("assistant conversation not found")
	ErrBusy     = errors.New("assistant busy or unavailable")
	ErrCapacity = errors.New("assistant capacity reached")
)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var conversationID = regexp.MustCompile(`^chat-[a-f0-9]{32}$`)
var turnID = regexp.MustCompile(`^turn-[a-f0-9]{32}$`)

type SettingsInput struct {
	aichat.Settings
	Enabled   bool    `json:"enabled"`
	Secret    *string `json:"secret,omitempty"`
	Revision  int     `json:"revision"`
	RequestID string  `json:"request_id"`
}
type SettingsView struct {
	aichat.Settings
	Enabled    bool `json:"enabled"`
	Configured bool `json:"configured"`
	Revision   int  `json:"revision"`
}
type Input struct {
	ConversationID string `json:"conversation_id,omitempty"`
	Revision       int    `json:"revision"`
	RequestID      string `json:"request_id"`
	Message        string `json:"message"`
	Locale         string `json:"locale"`
	Consent        bool   `json:"consent"`
}
type Conversation struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Title     string    `json:"title"`
	Revision  int       `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Turns     []Turn    `json:"turns,omitempty"`
}
type Turn struct {
	ID               string    `json:"id"`
	ConversationID   string    `json:"conversation_id"`
	RequestID        string    `json:"request_id"`
	Status           string    `json:"status"`
	Message          string    `json:"message"`
	Reply            string    `json:"reply,omitempty"`
	Model            string    `json:"model"`
	SettingsRevision int       `json:"settings_revision"`
	At               time.Time `json:"at"`
	FinishedAt       time.Time `json:"finished_at,omitzero"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
}
type Audit struct {
	At             time.Time `json:"at"`
	ActorID        string    `json:"actor_id"`
	Action         string    `json:"action"`
	ConversationID string    `json:"conversation_id,omitempty"`
	TurnID         string    `json:"turn_id,omitempty"`
	Revision       int       `json:"revision"`
}
type Page struct {
	Results []Conversation `json:"results"`
	Total   int            `json:"total"`
}
type AuditPage struct {
	Results []Audit `json:"results"`
	Total   int     `json:"total"`
}
type SubmitResult struct {
	ConversationID string `json:"conversation_id"`
	Revision       int    `json:"revision"`
	Turn           Turn   `json:"turn"`
}
