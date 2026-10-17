package gateway

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxCommandRecordBytes = 64 * 1024

// CommandRecord is a completed command line submitted at a recognized remote
// terminal prompt. It does not claim that the remote shell executed it.
type CommandRecord struct {
	ActorID     string    `json:"actor_id,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	ID          string    `json:"id"`
	Command     string    `json:"command"`
	SubmittedAt time.Time `json:"submitted_at"`
	Outcome     string    `json:"outcome"`
	RuleName    string    `json:"rule_name,omitempty"`
	ReviewedBy  string    `json:"reviewed_by,omitempty"`
	ReviewID    string    `json:"review_id,omitempty"`
}

type commandRecordEnvelope struct {
	SessionID  string `json:"session_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type commandRecordPayload struct {
	ActorID     string    `json:"actor_id,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	ID          string    `json:"id"`
	Command     string    `json:"command"`
	SubmittedAt time.Time `json:"submitted_at"`
	Outcome     string    `json:"outcome,omitempty"`
	RuleName    string    `json:"rule_name,omitempty"`
	ReviewedBy  string    `json:"reviewed_by,omitempty"`
	ReviewID    string    `json:"review_id,omitempty"`
}

var ErrInvalidCommandRequest = errors.New("invalid command audit request")

// appendCommand stores only encrypted command payloads. Session IDs remain
// visible for efficient authorization-scoped lookups.
func (b *Broker) appendCommand(sessionID string, submission commandSubmission, contexts ...*activeSession) error {
	command := strings.TrimSpace(submission.Command)
	if submission.Outcome == "" {
		submission.Outcome = "allowed"
	}
	if (command == "" && submission.Outcome != "blocked") || len(command) > maxCommandInputBytes || submission.SubmittedAt.IsZero() || !validCommandOutcome(submission.Outcome) || len(submission.RuleName) > 80 || len(submission.ReviewedBy) > 128 {
		return fmt.Errorf("invalid command audit record")
	}
	aead, err := commandAuditAEAD(b.vaultKey, sessionID)
	if err != nil {
		return err
	}
	if submission.ReviewID != "" && !validSessionID(submission.ReviewID) {
		return fmt.Errorf("invalid command review ID")
	}
	id, err := randomToken(18)
	if err != nil {
		return fmt.Errorf("create command audit ID: %w", err)
	}
	payload, err := json.Marshal(commandRecordPayload{ActorID: submission.ActorID, Actor: submission.Actor, ID: id, Command: command, SubmittedAt: submission.SubmittedAt.UTC(), Outcome: submission.Outcome, RuleName: submission.RuleName, ReviewedBy: submission.ReviewedBy, ReviewID: submission.ReviewID})
	if err != nil {
		return fmt.Errorf("encode command audit record: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("create command audit nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, []byte(sessionID))
	encoded, err := json.Marshal(commandRecordEnvelope{SessionID: sessionID, Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return fmt.Errorf("encode encrypted command audit record: %w", err)
	}
	b.commandAuditMu.Lock()
	defer b.commandAuditMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(b.commandPath), 0o700); err != nil {
		return fmt.Errorf("create command audit directory: %w", err)
	}
	file, err := os.OpenFile(b.commandPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open command audit index: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write command audit index: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync command audit index: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close command audit index: %w", err)
	}
	if b.commandAlert != nil && commandAlertState(submission) != "" {
		if len(contexts) != 1 || contexts[0] == nil {
			return fmt.Errorf("command alert context unavailable")
		}
		if err := b.commandAlert(commandAlertRecord(contexts[0], submission, id)); err != nil {
			return fmt.Errorf("persist command security metadata: %w", err)
		}
	}
	return nil
}

// ListCommands returns commands for an existing session. Authorization is
// enforced by the API layer before calling this method.
func (b *Broker) ListCommands(sessionID string, offset, limit int) ([]CommandRecord, int, error) {
	if err := validateCommandPagination(sessionID, offset, limit); err != nil {
		return nil, 0, err
	}
	records, err := b.readSessionRecords()
	if err != nil {
		return nil, 0, err
	}
	found := false
	for _, record := range records {
		if record.SessionID == sessionID {
			found = true
			break
		}
	}
	if !found {
		return nil, 0, ErrSessionNotFound
	}
	return b.readCommands(sessionID, offset, limit)
}

// ListCommandsForOperator exposes command records only to their session owner.
func (b *Broker) ListCommandsForOperator(sessionID, operatorID string, offset, limit int) ([]CommandRecord, int, error) {
	if err := validateCommandPagination(sessionID, offset, limit); err != nil {
		return nil, 0, err
	}
	if err := b.requireSessionOperator(sessionID, operatorID); err != nil {
		return nil, 0, err
	}
	return b.readCommands(sessionID, offset, limit)
}

func validateCommandPagination(sessionID string, offset, limit int) error {
	if !validSessionID(sessionID) || offset < 0 || limit < 1 || limit > 200 {
		return ErrInvalidCommandRequest
	}
	return nil
}

func (b *Broker) readCommands(sessionID string, offset, limit int) ([]CommandRecord, int, error) {
	b.commandAuditMu.Lock()
	defer b.commandAuditMu.Unlock()
	file, err := os.Open(b.commandPath)
	if errors.Is(err, os.ErrNotExist) {
		return []CommandRecord{}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open command audit index: %w", err)
	}
	defer file.Close()
	aead, err := commandAuditAEAD(b.vaultKey, sessionID)
	if err != nil {
		return nil, 0, err
	}
	commands := make([]CommandRecord, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var envelope commandRecordEnvelope
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil || !validSessionID(envelope.SessionID) {
			return nil, 0, fmt.Errorf("command audit index contains an invalid record")
		}
		if envelope.SessionID != sessionID {
			continue
		}
		if len(envelope.Nonce) != aead.NonceSize() || len(envelope.Ciphertext) < aead.Overhead() || len(envelope.Ciphertext) > maxCommandRecordBytes {
			return nil, 0, fmt.Errorf("command audit record is invalid")
		}
		plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, []byte(sessionID))
		if err != nil {
			return nil, 0, fmt.Errorf("authenticate command audit record")
		}
		var payload commandRecordPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return nil, 0, fmt.Errorf("command audit payload is invalid")
		}
		if payload.Outcome == "" {
			payload.Outcome = "allowed" // Backward compatibility with the original audit schema.
		}
		if !validSessionID(payload.ID) || (payload.Command == "" && payload.Outcome != "blocked") || len(payload.Command) > maxCommandInputBytes || payload.SubmittedAt.IsZero() || !validCommandOutcome(payload.Outcome) || len(payload.RuleName) > 80 || len(payload.ReviewedBy) > 128 || (payload.ReviewID != "" && !validSessionID(payload.ReviewID)) {
			return nil, 0, fmt.Errorf("command audit payload is invalid")
		}
		commands = append(commands, CommandRecord{ActorID: payload.ActorID, Actor: payload.Actor, ID: payload.ID, Command: payload.Command, SubmittedAt: payload.SubmittedAt, Outcome: payload.Outcome, RuleName: payload.RuleName, ReviewedBy: payload.ReviewedBy, ReviewID: payload.ReviewID})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("read command audit index: %w", err)
	}
	// A process restart drops in-memory review queues. If the session is no
	// longer active, do not present an unresolved request as awaiting approval.
	b.mu.Lock()
	_, sessionActive := b.sessions[sessionID]
	b.mu.Unlock()
	if !sessionActive {
		for i := range commands {
			if commands[i].Outcome == "pending" {
				commands[i].Outcome = "cancelled"
				commands[i].ReviewedBy = "system"
			}
		}
	}
	total := len(commands)
	sort.Slice(commands, func(i, j int) bool {
		if commands[i].SubmittedAt.Equal(commands[j].SubmittedAt) {
			return commands[i].ID > commands[j].ID
		}
		return commands[i].SubmittedAt.After(commands[j].SubmittedAt)
	})
	if offset >= total {
		return []CommandRecord{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return commands[offset:end], total, nil
}

func validCommandOutcome(outcome string) bool {
	switch outcome {
	case "allowed", "blocked", "pending", "approved", "denied", "timed_out", "cancelled":
		return true
	default:
		return false
	}
}

func commandAuditAEAD(vaultKey []byte, sessionID string) (cipher.AEAD, error) {
	if len(vaultKey) != 32 || !validSessionID(sessionID) {
		return nil, fmt.Errorf("a 32-byte vault key and valid session ID are required for command audit")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("jumpserver233/command-audit/v1\x00"))
	_, _ = hash.Write(vaultKey)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(sessionID))
	block, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("create command audit cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create command audit AEAD: %w", err)
	}
	return aead, nil
}
