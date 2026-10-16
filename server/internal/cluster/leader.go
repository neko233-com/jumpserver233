package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidClusterID      = errors.New("invalid cluster ID")
	ErrInvalidDatabaseConfig = errors.New("invalid cluster database configuration")
	ErrLeaseLost             = errors.New("cluster leader lease was lost")
	ErrLeaseNotHeld          = errors.New("cluster leader lease is not held")
)

// Lease holds a PostgreSQL session advisory lock on a dedicated connection.
// Keeping that connection open makes the lock exclusive to one active node.
type Lease struct {
	mu        sync.Mutex
	conn      *pgx.Conn
	clusterID string
	closed    bool
}

// TryAcquire opens a dedicated PostgreSQL session and tries to become the
// active node for clusterID. A false result means another node is active.
func TryAcquire(ctx context.Context, databaseURL, clusterID string) (*Lease, bool, error) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" || len(clusterID) > 128 {
		return nil, false, ErrInvalidClusterID
	}
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, false, ErrInvalidDatabaseConfig
	}
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["application_name"] = "jumpserver233-cluster-" + clusterID
	config.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, false, fmt.Errorf("connect to cluster database: %w", err)
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, clusterID).Scan(&acquired); err != nil {
		_ = conn.Close(context.Background())
		return nil, false, fmt.Errorf("acquire cluster leader lock: %w", err)
	}
	if !acquired {
		_ = conn.Close(context.Background())
		return nil, false, nil
	}
	return &Lease{conn: conn, clusterID: clusterID}, true, nil
}

// Check verifies the dedicated PostgreSQL session is still usable. Session
// advisory locks are released by PostgreSQL when that session ends.
func (l *Lease) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.conn == nil {
		return ErrLeaseLost
	}
	var alive int
	if err := l.conn.QueryRow(ctx, `SELECT 1`).Scan(&alive); err != nil || alive != 1 {
		if err == nil {
			err = errors.New("unexpected database response")
		}
		return fmt.Errorf("%w: %v", ErrLeaseLost, err)
	}
	return nil
}

// Close releases the advisory lock and closes its dedicated session.
func (l *Lease) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.conn == nil {
		return nil
	}
	l.closed = true
	var unlocked bool
	unlockErr := l.conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, l.clusterID).Scan(&unlocked)
	closeErr := l.conn.Close(ctx)
	if unlockErr != nil {
		return fmt.Errorf("release cluster leader lock: %w", unlockErr)
	}
	if !unlocked {
		return ErrLeaseNotHeld
	}
	if closeErr != nil {
		return fmt.Errorf("close cluster leader session: %w", closeErr)
	}
	return nil
}
