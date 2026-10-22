package nativeaccess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/url"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"golang.org/x/crypto/ssh"
)

// Client probes and helper scripts execute only on the selected asset through
// the same job boundary as Web/CLI exec: source, grants, binding, directory,
// command denial/review, cancellation and encrypted history remain authoritative.
func (s *Server) exec(parent context.Context, c *apiClient, ch ssh.Channel, command string) error {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	id, release, e := c.holdTarget(ctx)
	if e != nil {
		return e
	}
	defer release()
	select {
	case c.execSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.execSlots }()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	var job jobs.Job
	if e = c.json(ctx, "POST", "/api/v1/ops/jobs", jobs.Input{AssetID: id, Command: command, TimeoutSeconds: 60, RequestID: "native-" + hex.EncodeToString(nonce[:])}, &job); e != nil {
		return e
	}
	endpoint := "/api/v1/ops/jobs/" + url.PathEscape(job.ID)
	finished := false
	defer func() {
		if !finished {
			_ = c.json(context.Background(), "DELETE", endpoint, nil, nil)
		}
	}()
	// EOF alone is not cancellation: normal exec clients close their stdin.
	// Channel Close closes the request stream and cancels the parent instead.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		switch job.State {
		case "pending_review", "running":
		default:
			finished = true
			_, _ = io.WriteString(ch, job.Stdout)
			_, _ = io.WriteString(ch.Stderr(), job.Stderr)
			code := job.ExitCode
			if code < 0 || job.State != "succeeded" && code == 0 {
				code = 1
			}
			exitStatus(ch, uint32(code))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if e = c.json(ctx, "GET", endpoint, nil, &job); e != nil {
			return e
		}
	}
}
