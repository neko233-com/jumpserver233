package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"golang.org/x/term"
)

func shareText(en, zh string) string {
	if strings.Contains(strings.ToLower(os.Getenv("LC_ALL")+os.Getenv("LC_MESSAGES")+os.Getenv("LANG")), "zh") {
		return zh
	}
	return en
}
func runShare(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(endpoint)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(args) >= 2 && args[0] == "join" {
		f := flag.NewFlagSet("share join", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		control := false
		f.BoolVar(&control, "control", false, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 {
			return errors.New("invalid share join flags")
		}
		code := os.Getenv("JMS_SHARE_CODE")
		if code == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("JMS_SHARE_CODE or an interactive code prompt is required")
			}
			fmt.Fprint(os.Stderr, shareText("Invitation code: ", "邀请验证码："))
			raw, e := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if e != nil {
				return e
			}
			code = string(raw)
		}
		joinCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		joined, e := client.JoinShare(joinCtx, args[1], code)
		cancel()
		code = ""
		if e != nil {
			return e
		}
		conn, e := client.DialSharedTerminal(ctx, joined)
		if e != nil {
			return e
		}
		defer conn.CloseNow()
		if control && joined.Member.Mode != "read_write" {
			return errors.New("this invitation does not allow input control")
		}
		conn.SetReadLimit(64 * 1024)
		streamCtx, cancelStream := context.WithCancel(ctx)
		defer cancelStream()
		var writable atomic.Bool
		started := false
		requested := false
		var rawState *term.State
		defer func() {
			if rawState != nil {
				_ = term.Restore(int(os.Stdin.Fd()), rawState)
			}
		}()
		fmt.Fprintln(os.Stderr, shareText("Shared session connected. Ctrl+] leaves input mode; input control must be reclaimed by the owner after a writer leaves.", "已连接共享会话。输入模式下按 Ctrl+] 离开；写入者离开后需由所有者收回输入控制。"))
		for {
			kind, data, e := conn.Read(streamCtx)
			if e != nil {
				if ctx.Err() != nil || streamCtx.Err() != nil {
					return nil
				}
				fmt.Fprintln(os.Stderr, shareText("Shared session ended.", "共享会话已结束。"))
				return nil
			}
			if kind == websocket.MessageBinary {
				if _, e = os.Stdout.Write(data); e != nil {
					return e
				}
				continue
			}
			var message struct {
				Type              string `json:"type"`
				Controller        string `json:"controller"`
				RuleName          string `json:"rule_name"`
				DirectoryRequired bool   `json:"directory_required"`
			}
			if json.Unmarshal(data, &message) != nil {
				return errors.New("invalid shared terminal frame")
			}
			switch message.Type {
			case "share_state":
				own := message.Controller == joined.Member.ID
				writable.Store(own)
				if control && joined.Member.Mode == "read_write" && !requested {
					requested = true
					if e = conn.Write(streamCtx, websocket.MessageText, []byte(`{"type":"take_control"}`)); e != nil {
						return e
					}
				}
				if own && control && !started {
					started = true
					if term.IsTerminal(int(os.Stdin.Fd())) {
						rawState, e = term.MakeRaw(int(os.Stdin.Fd()))
						if e != nil {
							return e
						}
					}
					go func() {
						buffer := make([]byte, 4096)
						for {
							n, err := os.Stdin.Read(buffer)
							if n > 0 {
								chunk := buffer[:n]
								end := bytes.IndexByte(chunk, 0x1d)
								if end >= 0 {
									chunk = chunk[:end]
								}
								if len(chunk) > 0 && writable.Load() {
									if conn.Write(streamCtx, websocket.MessageBinary, chunk) != nil {
										cancelStream()
										return
									}
								}
								if end >= 0 {
									cancelStream()
									return
								}
							}
							if err != nil {
								return
							}
						}
					}()
				}
			case "share_control_required":
				writable.Store(false)
			case "share_control_busy":
				return errors.New(shareText("A command review is pending; join without --control or retry after the review finishes.", "当前有命令等待复核，请先以只读方式加入或在复核结束后重试。"))
			case "command_blocked":
				fmt.Fprint(os.Stderr, commandBlockedNotice(message.RuleName, message.DirectoryRequired))
			case "command_review_pending", "command_review_approved", "command_review_denied", "command_review_timed_out":
				fmt.Fprint(os.Stderr, commandReviewNotice(message.Type, message.RuleName))
			default:
				return errors.New("unsupported shared terminal frame")
			}
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return executeShare(requestCtx, client, args, os.Stdout)
}
func executeShare(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return errors.New("usage: jms share create SESSION_ID --users USER1,USER2 [--mode read_only|read_write] [--minutes 10] | state SESSION_ID | revoke SHARE_ID | kick MEMBER_ID | reclaim SESSION_ID | events SESSION_ID | join SHARE_ID [--control]")
	}
	var result any
	var e error
	switch args[0] {
	case "create":
		f := flag.NewFlagSet("share create", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		users, mode := "", "read_only"
		minutes := 10
		f.StringVar(&users, "users", "", "")
		f.StringVar(&mode, "mode", "read_only", "")
		f.IntVar(&minutes, "minutes", 10, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || users == "" || minutes < 1 || minutes > 1440 || (mode != "read_only" && mode != "read_write") {
			return errors.New("invalid share create flags")
		}
		names := strings.Split(users, ",")
		for i := range names {
			names[i] = strings.TrimSpace(names[i])
		}
		result, e = c.CreateShare(ctx, args[1], sessionclient.ShareInput{Mode: mode, Minutes: minutes, Users: names})
	case "state":
		if len(args) != 2 {
			return errors.New("invalid share state flags")
		}
		result, e = c.ShareState(ctx, args[1])
	case "revoke":
		if len(args) != 2 {
			return errors.New("invalid share revoke flags")
		}
		e = c.RevokeShare(ctx, args[1])
	case "kick":
		if len(args) != 2 {
			return errors.New("invalid share kick flags")
		}
		e = c.KickShareMember(ctx, args[1])
	case "reclaim":
		if len(args) != 2 {
			return errors.New("invalid share reclaim flags")
		}
		e = c.ReclaimShare(ctx, args[1])
	case "events":
		f := flag.NewFlagSet("share events", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		offset, limit := 0, 50
		f.IntVar(&offset, "offset", 0, "")
		f.IntVar(&limit, "limit", 50, "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || offset < 0 || offset > 1000000 || limit < 1 || limit > 100 {
			return errors.New("invalid share event flags")
		}
		result, e = c.ShareEvents(ctx, args[1], offset, limit)
	default:
		return errors.New("unsupported share command")
	}
	if e != nil {
		return e
	}
	if result != nil {
		return json.NewEncoder(out).Encode(result)
	}
	return nil
}
