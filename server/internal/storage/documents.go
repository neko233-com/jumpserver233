package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	documentsTable = "jms233_state_documents"
	operationLimit = 5 * time.Second
)

var (
	ErrDocumentNotFound = errors.New("shared state document not found")
	ErrInvalidDocument  = errors.New("invalid shared state document")
)

// Documents stores versioned product state as PostgreSQL JSONB documents.
// Each Save is one atomic upsert. The namespace keeps independent clusters
// from sharing data when they use the same PostgreSQL database.
type Documents struct {
	db        *sql.DB
	namespace string
	prefix    string
}

// Scoped reuses the active node's database pool while separating every document
// key. The root owns the pool; closing a scoped view never closes shared state.
func (d *Documents) Scoped(scope string) (*Documents, error) {
	if d == nil || scope == "" || len(scope) > 40 {
		return nil, ErrInvalidDocument
	}
	for _, r := range scope {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return nil, ErrInvalidDocument
		}
	}
	if d.prefix != "" {
		return nil, ErrInvalidDocument
	}
	return &Documents{db: d.db, namespace: d.namespace, prefix: scope + ":"}, nil
}
func (d *Documents) documentKey(key string) (string, error) {
	if e := validateKey(key); e != nil {
		return "", e
	}
	key = d.prefix + key
	if e := validateKey(key); e != nil {
		return "", e
	}
	return key, nil
}

func OpenPostgres(ctx context.Context, databaseURL, namespace string) (*Documents, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" || len(namespace) > 128 {
		return nil, fmt.Errorf("%w: invalid namespace", ErrInvalidDocument)
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open shared state database: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	openCtx, cancel := context.WithTimeout(ctx, operationLimit)
	defer cancel()
	if err := db.PingContext(openCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect shared state database: %w", err)
	}
	tx, err := db.BeginTx(openCtx, nil)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("begin shared state migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(openCtx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 1))`, "jms233-state-schema-v1",
	); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("lock shared state migration: %w", err)
	}
	_, err = tx.ExecContext(openCtx, `
		CREATE TABLE IF NOT EXISTS jms233_state_documents (
			namespace TEXT NOT NULL,
			document_key TEXT NOT NULL,
			body JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (namespace, document_key)
		)`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize shared state database: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("commit shared state migration: %w", err)
	}
	return &Documents{db: db, namespace: namespace}, nil
}

func (d *Documents) Load(key string) ([]byte, error) {
	qualified, err := d.documentKey(key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	var body []byte
	err = d.db.QueryRowContext(ctx,
		`SELECT body FROM jms233_state_documents WHERE namespace = $1 AND document_key = $2`,
		d.namespace, qualified,
	).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load shared state document %q: %w", key, err)
	}
	return body, nil
}

// LoadOrImport reads a shared document, importing a valid legacy JSON file
// only when no database row exists. A competing initializer wins atomically.
func (d *Documents) LoadOrImport(key, legacyPath string) ([]byte, error) {
	qualified, keyError := d.documentKey(key)
	if keyError != nil {
		return nil, keyError
	}
	body, err := d.Load(key)
	if err == nil {
		return body, nil
	}
	if !errors.Is(err, ErrDocumentNotFound) {
		return nil, err
	}
	legacy, err := os.ReadFile(legacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read legacy state document %q: %w", key, err)
	}
	if !json.Valid(legacy) {
		return nil, fmt.Errorf("%w: legacy document %q is not valid JSON", ErrInvalidDocument, key)
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO jms233_state_documents (namespace, document_key, body)
		VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (namespace, document_key) DO NOTHING`,
		d.namespace, qualified, string(legacy),
	)
	if err != nil {
		return nil, fmt.Errorf("import legacy state document %q: %w", key, err)
	}
	return d.Load(key)
}

func (d *Documents) Save(key string, body []byte) error {
	qualified, err := d.documentKey(key)
	if err != nil {
		return err
	}
	if !json.Valid(body) {
		return fmt.Errorf("%w: document %q is not valid JSON", ErrInvalidDocument, key)
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO jms233_state_documents (namespace, document_key, body, updated_at)
		VALUES ($1, $2, $3::jsonb, NOW())
		ON CONFLICT (namespace, document_key)
		DO UPDATE SET body = EXCLUDED.body, updated_at = NOW()`,
		d.namespace, qualified, string(body),
	)
	if err != nil {
		return fmt.Errorf("save shared state document %q: %w", key, err)
	}
	return nil
}

func (d *Documents) Delete(key string) error {
	qualified, err := d.documentKey(key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	if _, err := d.db.ExecContext(ctx,
		`DELETE FROM jms233_state_documents WHERE namespace = $1 AND document_key = $2`,
		d.namespace, qualified,
	); err != nil {
		return fmt.Errorf("delete shared state document %q: %w", key, err)
	}
	return nil
}

func (d *Documents) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	if err := d.db.PingContext(ctx); err != nil {
		return fmt.Errorf("shared state database is unavailable: %w", err)
	}
	return nil
}

func (d *Documents) Close() error {
	if d.prefix != "" {
		return nil
	}
	return d.db.Close()
}

func validateKey(key string) error {
	if key == "" || len(key) > 80 || strings.TrimSpace(key) != key {
		return fmt.Errorf("%w: invalid document key", ErrInvalidDocument)
	}
	return nil
}
