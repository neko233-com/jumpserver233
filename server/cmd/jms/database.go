package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/databasequery"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const databaseUsage = "usage: jms db <asset-id> [--write] [--timeout 30] [--rows 500] [--params '<JSON array>'] < query.sql (JSON result on stdout)"

func runDatabase(args []string) error {
	serverURL := os.Getenv("JMS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(serverURL)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return executeDatabase(ctx, client, args, os.Stdin, os.Stdout, os.Stderr)
}
func executeDatabase(ctx context.Context, client *sessionclient.Client, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 1 || args[0] == "" {
		return errors.New(databaseUsage)
	}
	asset := args[0]
	in := databasequery.Input{Input: sqlclient.Input{ReadOnly: true, RowLimit: 500, TimeoutSeconds: 30}}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--write":
			in.ReadOnly = false
		case "--timeout", "--rows", "--params":
			option := args[i]
			i++
			if i >= len(args) {
				return errors.New(databaseUsage)
			}
			switch option {
			case "--params":
				if json.Unmarshal([]byte(args[i]), &in.Parameters) != nil {
					return sqlclient.ErrInvalid
				}
			case "--timeout":
				v, e := strconv.Atoi(args[i])
				if e != nil {
					return sqlclient.ErrInvalid
				}
				in.TimeoutSeconds = v
			case "--rows":
				v, e := strconv.Atoi(args[i])
				if e != nil {
					return sqlclient.ErrInvalid
				}
				in.RowLimit = v
			}
		default:
			return errors.New(databaseUsage)
		}
	}
	raw, e := io.ReadAll(io.LimitReader(stdin, sqlclient.MaxSQLBytes+1))
	if e != nil {
		return e
	}
	in.SQL = string(raw)
	if sqlclient.ValidateShape(in.Input) != nil {
		return sqlclient.ErrInvalid
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	in.RequestID = hex.EncodeToString(id[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds)*time.Second+11*time.Minute)
	defer cancel()
	var session databasequery.SessionResponse
	for {
		session, e = client.CreateDatabaseSession(ctx, asset)
		if e == nil {
			break
		}
		var review *sessionclient.AccessReviewPendingError
		if !errors.As(e, &review) {
			return e
		}
		fmt.Fprintln(stderr, "Database login awaiting administrator review.")
		state, waitErr := client.WaitForAccessReview(ctx, review.ReviewID)
		if waitErr != nil {
			return waitErr
		}
		if state != "approved" {
			return errors.New("database login review did not approve access")
		}
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = client.DatabaseRequest(cleanup, "DELETE", "/api/v1/database-sessions", session.Token, nil, nil)
	}()
	if !in.ReadOnly && !session.ReadOnly && (session.Protocol == "mysql" || session.Protocol == "mariadb") {
		locale := strings.ToLower(os.Getenv("LANG") + os.Getenv("LC_ALL"))
		if strings.Contains(locale, "zh") {
			fmt.Fprintln(stderr, "MySQL/MariaDB 写入使用自动提交；取消不能撤销已完成的变更。重试前请核对事务结果。")
		} else {
			fmt.Fprintln(stderr, "MySQL/MariaDB writes use auto-commit. Cancellation cannot undo completed changes; reconcile the outcome before retrying.")
		}
	}
	if !in.ReadOnly && !session.ReadOnly && session.Protocol == "sqlserver" {
		locale := strings.ToLower(os.Getenv("LANG") + os.Getenv("LC_ALL"))
		if strings.Contains(locale, "zh") {
			fmt.Fprintln(stderr, "SQL Server 批次使用服务端事务语义；报错或取消后仍可能保留变更，重试前请核对结果。")
		} else {
			fmt.Fprintln(stderr, "SQL Server batches use server-managed transactions. Changes may persist after failure or cancellation; reconcile the outcome before retrying.")
		}
	}
	if !in.ReadOnly && !session.ReadOnly && (session.Protocol == "clickhouse" || session.Protocol == "redis" || session.Protocol == "mongodb") {
		locale := strings.ToLower(os.Getenv("LANG") + os.Getenv("LC_ALL"))
		if strings.Contains(locale, "zh") {
			fmt.Fprintln(stderr, "数据库写入无法保证回滚；失败或取消后请核对结果再重试。")
		} else {
			fmt.Fprintln(stderr, "Database writes have no guaranteed rollback. Reconcile results after failure or cancellation before retrying.")
		}
	}
	in.Dialect = session.Protocol
	if sqlclient.ValidateInput(in.Input) != nil {
		return sqlclient.ErrInvalid
	}
	job, e := client.SubmitDatabaseQuery(ctx, asset, session.Token, in)
	if e != nil {
		return e
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, e := client.GetDatabaseQuery(ctx, job.ID)
		if e != nil {
			return e
		}
		switch result.State {
		case "queued", "running", "awaiting_review":
			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		default:
			if e = json.NewEncoder(stdout).Encode(result); e != nil {
				return e
			}
			if result.State != "completed" {
				return fmt.Errorf("database query %s", result.State)
			}
			return nil
		}
	}
}
