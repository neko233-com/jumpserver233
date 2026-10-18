package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"golang.org/x/term"
)

type outbound struct {
	typ  websocket.MessageType
	data []byte
}

type inbound struct {
	data []byte
	err  error
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var remote *remoteExitError
		if errors.As(err, &remote) {
			os.Exit(remote.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "login-audit" {
		return runLoginAudit(args[1:])
	}
	if len(args) > 0 && args[0] == "platform-notifications" {
		return runNotifications(args[1:], true)
	}
	if len(args) > 0 && args[0] == "monitor" {
		return runMonitor(args[1:])
	}
	if len(args) > 0 && args[0] == "ticket" {
		return runTickets(args[1:])
	}
	if len(args) > 0 && args[0] == "notifications" {
		return runNotifications(args[1:])
	}
	selector := ""
	if len(args) > 0 && args[0] == "--account" {
		if len(args) < 4 || strings.TrimSpace(args[1]) == "" {
			return errors.New("usage: jms --account USERNAME_OR_ID ssh|exec|plugin|accounts ASSET ...")
		}
		selector, args = args[1], args[2:]
	}
	if selector != "" && args[0] != "ssh" && args[0] != "exec" && args[0] != "plugin" && args[0] != "accounts" && args[0] != "agent-events" {
		return errors.New("managed account selection currently requires an SSH operation")
	}
	if len(args) > 0 && args[0] == "account" {
		return runManagedAccounts(args[1:])
	}
	if len(args) > 0 && args[0] == "accounts" {
		return runAccounts(args[1:], selector)
	}
	if len(args) > 0 && args[0] == "share" {
		return runShare(args[1:])
	}
	if len(args) > 0 && args[0] == "agent-events" {
		return runAgentEvents(args[1:], selector)
	}
	if len(args) > 0 && args[0] == "plugin" {
		return runPlugins(args[1:], selector)
	}
	if len(args) > 0 && args[0] == "rdp" {
		return runDesktop(args[1:])
	}
	protocol := ""
	if len(args) > 0 && args[0] == "telnet" {
		protocol = "telnet"
		args = append([]string(nil), args...)
		args[0] = "ssh"
	}
	var selection *kubeclient.Selection
	if len(args) > 0 && args[0] == "k8s" {
		if len(args) < 2 {
			return errors.New("usage: jms k8s <asset-id> --namespace <namespace> --pod <pod> [--container <container>]")
		}
		f := flag.NewFlagSet("k8s", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		v := kubeclient.Selection{}
		f.StringVar(&v.Namespace, "namespace", "default", "")
		f.StringVar(&v.Pod, "pod", "", "")
		f.StringVar(&v.Container, "container", "", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 || v.Pod == "" {
			return errors.New("invalid Kubernetes target flags")
		}
		selection = &v
		args = []string{"ssh", args[1]}
	}
	if len(args) > 0 && args[0] == "db" {
		return runDatabase(args[1:])
	}
	if len(args) > 0 && args[0] == "exec" {
		return runExec(args[1:], selector)
	}
	if len(args) != 2 || args[0] != "ssh" || strings.TrimSpace(args[1]) == "" {
		return errors.New("usage: jms ssh <asset-id> | jms telnet <asset-id> | jms k8s <asset-id> --namespace NS --pod POD [--container NAME] | jms exec <asset-id> [--timeout 60] [--json] -- <command> | jms db <asset-id> < query.sql")
	}
	stdin := int(os.Stdin.Fd())
	if selection == nil && protocol != "telnet" && !term.IsTerminal(stdin) {
		return errors.New("jms ssh requires an interactive terminal")
	}
	cols, rows, err := term.GetSize(stdin)
	if err != nil {
		cols, rows = 80, 24
	}
	serverURL := os.Getenv("JMS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	client, err := clientFromEnvironment(serverURL, selector)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var session gateway.CreatedSession
	notice := func(state string) string {
		message := terminalReviewNotice(state, selection != nil)
		if protocol == "telnet" {
			return strings.ReplaceAll(message, "SSH", "Telnet")
		}
		return message
	}
	for {
		session, err = client.CreateSession(ctx, gateway.CreateRequest{AssetID: args[1], Protocol: protocol, Cols: cols, Rows: rows, Kubernetes: selection})
		if err == nil {
			break
		}
		var pending *sessionclient.AccessReviewPendingError
		if !errors.As(err, &pending) {
			return err
		}
		fmt.Fprintln(os.Stderr, notice("pending"))
		state, waitErr := client.WaitForAccessReview(ctx, pending.ReviewID)
		if waitErr != nil {
			return waitErr
		}
		if state != "approved" {
			return fmt.Errorf("%s", notice(state))
		}
		fmt.Fprintln(os.Stderr, notice("approved"))
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = client.CloseSession(closeCtx, session.SessionID)
	}()
	fmt.Fprintln(os.Stderr, shareText("Session ID: "+session.SessionID+". Use jms share in another terminal to manage collaboration.", "会话 ID："+session.SessionID+"。可在另一终端使用 jms share 管理协作。"))
	conn, err := client.DialTerminal(ctx, session)
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 * 1024)
	if term.IsTerminal(stdin) {
		state, err := term.MakeRaw(stdin)
		if err != nil {
			return fmt.Errorf("switch local terminal to raw mode: %w", err)
		}
		defer func() { _ = term.Restore(stdin, state) }()
	}
	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()

	writes := make(chan outbound, 16)
	var writable atomic.Bool
	writable.Store(true)
	reads := make(chan inbound, 8)
	writerErr := make(chan error, 1)
	go func() {
		for {
			select {
			case frame := <-writes:
				if err := conn.Write(streamCtx, frame.typ, frame.data); err != nil {
					writerErr <- err
					return
				}
			case <-streamCtx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			typ, data, err := conn.Read(streamCtx)
			if err != nil {
				select {
				case reads <- inbound{err: err}:
				case <-streamCtx.Done():
				}
				return
			}
			if typ == websocket.MessageText {
				var notice struct {
					Controller string `json:"controller"`
					Type       string `json:"type"`
					RuleName   string `json:"rule_name"`
				}
				if json.Unmarshal(data, &notice) != nil {
					select {
					case reads <- inbound{err: fmt.Errorf("server sent an unsupported terminal frame")}:
					case <-streamCtx.Done():
					}
					return
				}
				var message string
				switch notice.Type {
				case "share_controller", "share_control_required":
					own := notice.Type == "share_controller" && notice.Controller == ""
					writable.Store(own)
					if own {
						message = shareText("\r\nInput control returned to you.\r\n", "\r\n输入控制已交还给你。\r\n")
					} else {
						message = shareText("\r\nAnother participant controls input. Use jms share reclaim SESSION_ID in another terminal to reclaim it.\r\n", "\r\n其他参与者拥有输入控制，可在另一终端使用 jms share reclaim SESSION_ID 取回。\r\n")
					}
				case "command_blocked":
					message = commandBlockedNotice(notice.RuleName)
				case "command_review_pending", "command_review_approved", "command_review_denied", "command_review_timed_out":
					message = commandReviewNotice(notice.Type, notice.RuleName)
				default:
					select {
					case reads <- inbound{err: fmt.Errorf("server sent an unsupported terminal frame")}:
					case <-streamCtx.Done():
					}
					return
				}
				data = []byte(message)
			} else if typ != websocket.MessageBinary {
				select {
				case reads <- inbound{err: fmt.Errorf("server sent an unsupported terminal frame")}:
				case <-streamCtx.Done():
				}
				return
			}
			select {
			case reads <- inbound{data: data}:
			case <-streamCtx.Done():
				return
			}
		}
	}()
	queue := func(frame outbound) bool {
		select {
		case writes <- frame:
			return true
		case <-streamCtx.Done():
			return false
		default:
			return false
		}
	}
	queueResize := func(width, height int) bool {
		frame, marshalErr := jsonMarshalResize(width, height)
		if marshalErr != nil {
			return false
		}
		return queue(outbound{typ: websocket.MessageText, data: frame})
	}
	if !queueResize(cols, rows) {
		return errors.New("could not initialize terminal size")
	}
	go func() {
		buffer := make([]byte, 4096)
		for {
			count, err := os.Stdin.Read(buffer)
			if count > 0 && writable.Load() {
				data := append([]byte(nil), buffer[:count]...)
				select {
				case writes <- outbound{typ: websocket.MessageBinary, data: data}:
				case <-streamCtx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					writerErr <- err
				}
				return
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case frame := <-reads:
			if frame.err != nil {
				if isTerminalClosed(frame.err) {
					return nil
				}
				return fmt.Errorf("SSH terminal disconnected: %w", frame.err)
			}
			if _, err := os.Stdout.Write(frame.data); err != nil {
				return fmt.Errorf("write terminal output: %w", err)
			}
		case err := <-writerErr:
			if isTerminalClosed(err) {
				return nil
			}
			return fmt.Errorf("write terminal input: %w", err)
		case <-ticker.C:
			width, height, sizeErr := term.GetSize(stdin)
			if sizeErr == nil && (width != cols || height != rows) {
				if !queueResize(width, height) {
					return errors.New("could not update terminal size")
				}
				cols, rows = width, height
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func clientFromEnvironment(serverURL string, selected ...string) (*sessionclient.Client, error) {
	token := os.Getenv("JMS_TOKEN")
	keyID := os.Getenv("JMS_ACCESS_KEY_ID")
	secret := os.Getenv("JMS_ACCESS_KEY_SECRET")
	if keyID != "" || secret != "" {
		if token != "" {
			return nil, errors.New("use either JMS_TOKEN or AccessKey credentials, not both")
		}
		if keyID == "" || secret == "" {
			return nil, errors.New("JMS_ACCESS_KEY_ID and JMS_ACCESS_KEY_SECRET must both be set")
		}
		client, err := sessionclient.NewWithAccessKey(serverURL, keyID, secret)
		if err != nil {
			return nil, err
		}
		return selectedClient(client, selected)
	}
	client, err := sessionclient.New(serverURL, token)
	if err != nil {
		return nil, err
	}
	return selectedClient(client, selected)
}

func selectedClient(client *sessionclient.Client, selected []string) (*sessionclient.Client, error) {
	client, e := client.WithOrganization(os.Getenv("JMS_ORG_ID"))
	if e != nil {
		return nil, e
	}
	selector := os.Getenv("JMS_ACCOUNT")
	if len(selected) > 0 && selected[0] != "" {
		selector = selected[0]
	}
	return client.WithManagedAccount(selector)
}

func commandBlockedNotice(ruleName string) string {
	locale := strings.ToLower(os.Getenv("LC_ALL") + " " + os.Getenv("LC_MESSAGES") + " " + os.Getenv("LANG"))
	if strings.Contains(locale, "zh") {
		if ruleName != "" {
			return fmt.Sprintf("\r\n命令已被规则“%s”拒绝。\r\n", ruleName)
		}
		return "\r\n命令已被策略拒绝。\r\n"
	}
	if ruleName != "" {
		return fmt.Sprintf("\r\nCommand blocked by rule: %s\r\n", ruleName)
	}
	return "\r\nCommand blocked by policy.\r\n"
}

func commandReviewNotice(noticeType, ruleName string) string {
	locale := strings.ToLower(os.Getenv("LC_ALL") + " " + os.Getenv("LC_MESSAGES") + " " + os.Getenv("LANG"))
	if strings.Contains(locale, "zh") {
		switch noticeType {
		case "command_review_pending":
			if ruleName != "" {
				return fmt.Sprintf("\r\n命令正在等待管理员复核（规则：%s）。复核期间输入会被暂停。\r\n", ruleName)
			}
			return "\r\n命令正在等待管理员复核。复核期间输入会被暂停。\r\n"
		case "command_review_approved":
			return "\r\n管理员已批准该命令，正在提交。\r\n"
		case "command_review_timed_out":
			return "\r\n命令复核超时，已取消执行。\r\n"
		default:
			return "\r\n管理员已拒绝该命令。\r\n"
		}
	}
	switch noticeType {
	case "command_review_pending":
		if ruleName != "" {
			return fmt.Sprintf("\r\nCommand is waiting for administrator review (rule: %s). Input is paused.\r\n", ruleName)
		}
		return "\r\nCommand is waiting for administrator review. Input is paused.\r\n"
	case "command_review_approved":
		return "\r\nCommand approved by an administrator and submitted.\r\n"
	case "command_review_timed_out":
		return "\r\nCommand review timed out; execution was cancelled.\r\n"
	default:
		return "\r\nCommand denied by an administrator.\r\n"
	}
}

func accessReviewNotice(state string) string {
	locale := strings.ToLower(os.Getenv("LC_ALL") + " " + os.Getenv("LC_MESSAGES") + " " + os.Getenv("LANG"))
	if strings.Contains(locale, "zh") {
		switch state {
		case "pending":
			return "SSH 登录正在等待管理员复核；批准后将自动继续连接。"
		case "approved":
			return "管理员已批准 SSH 登录，正在继续连接。"
		case "denied":
			return "管理员已拒绝 SSH 登录。"
		default:
			return "SSH 登录复核已过期，未建立会话。"
		}
	}
	switch state {
	case "pending":
		return "SSH login is waiting for administrator review; the connection will continue if approved."
	case "approved":
		return "SSH login approved; continuing the connection."
	case "denied":
		return "SSH login was denied by an administrator."
	default:
		return "SSH login review expired; no session was opened."
	}
}

func terminalReviewNotice(state string, kubernetes bool) string {
	message := accessReviewNotice(state)
	if kubernetes {
		return strings.ReplaceAll(message, "SSH", "Kubernetes")
	}
	return message
}

func isTerminalClosed(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || websocket.CloseStatus(err) != -1
}

func jsonMarshalResize(cols, rows int) ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Cols int    `json:"cols"`
		Rows int    `json:"rows"`
	}{Type: "resize", Cols: cols, Rows: rows})
}
