package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func tlsSettings(host, ca string) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if ca != "" {
		certificates, e := parseCA(ca)
		if e != nil {
			return nil, e
		}
		for _, certificate := range certificates {
			roots.AddCert(certificate)
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots}, nil
}
func parseCA(value string) ([]*x509.Certificate, error) {
	if value == "" {
		return nil, nil
	}
	raw := []byte(strings.TrimSpace(value))
	out := []*x509.Certificate{}
	for len(raw) > 0 {
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalid
		}
		certificate, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, ErrInvalid
		}
		out = append(out, certificate)
		raw = bytes.TrimSpace(rest)
	}
	if len(out) == 0 {
		return nil, ErrInvalid
	}
	return out, nil
}
func checkOutbound(ctx context.Context, v Outbound) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if v.Guard != nil {
		return v.Guard()
	}
	return nil
}
func titleAndBody(v Outbound) (string, string) {
	zh := v.Language == "zh-CN"
	titles := map[string][2]string{"approvals": {"Approval required", "有待处理审批"}, "tickets": {"Access request update", "访问工单更新"}, "jobs": {"Job result", "作业结果"}, "rotation": {"Credential rotation result", "账号改密结果"}, "security": {"Security notification", "安全通知"}, "system": {"System notification", "系统通知"}}
	pair, ok := titles[v.Message.Topic]
	if !ok {
		pair = titles["system"]
	}
	i := 0
	if zh {
		i = 1
	}
	title := pair[i]
	if v.VerificationCode != "" {
		if zh {
			return "验证联系方式", "验证码：" + v.VerificationCode + "\n10 分钟内有效，仅可使用一次。若非您本人操作，请忽略。"
		}
		return "Verify your contact", "Verification code: " + v.VerificationCode + "\nValid for 10 minutes and one use. Ignore this message if you did not request it."
	}
	states := map[string][2]string{"submitted": {"Submitted", "已提交"}, "amended": {"Request adjusted", "申请已调整"}, "approve": {"Approval stage completed", "当前审批阶段已通过"}, "reject": {"Rejected", "已拒绝"}, "approved": {"Approved", "已批准"}, "revoked": {"Revoked", "已撤销"}, "expired": {"Expired", "已过期"}, "cancelled": {"Cancelled", "已取消"}, "stale": {"Request needs resubmission", "申请需重新提交"}, "commented": {"New comment", "有新评论"}, "succeeded": {"Succeeded", "成功"}, "failed": {"Failed", "失败"}, "partial": {"Partially succeeded", "部分成功"}, "interrupted": {"Interrupted", "已中断"}, "recovery_required": {"Recovery required", "需要恢复"}, "completed": {"Completed", "已完成"}, "test": {"Test notification", "测试通知"}, "cancellation_requested": {"Cancellation requested", "已请求取消"}, "revocation_started": {"Revocation started", "已开始撤销"}}
	status := [2]string{"Updated", "已更新"}
	if p, ok := states[v.Message.State]; ok {
		status = p
	}
	body := title + "\n" + status[i]
	if v.Message.Name != "" {
		body += "\n" + v.Message.Name
	}
	if v.Message.Source.ID != "" {
		body += "\nID: " + v.Message.Source.ID
	}
	body += "\nUTC: " + v.Message.At.UTC().Format(time.RFC3339)
	link := v.Message.Link
	if u, e := url.Parse(v.SiteURL); e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		link = strings.TrimRight(v.SiteURL, "/") + link
	}
	if link != "" {
		body += "\n" + link
	}
	return title, body
}
func TransportSend(ctx context.Context, v Outbound) Outcome {
	if e := checkOutbound(ctx, v); e != nil {
		return Outcome{State: "suppressed", Code: "permission_changed"}
	}
	if !idPattern.MatchString(v.ID) || v.Settings.Validate() != nil {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	switch v.Channel {
	case "email":
		return sendSMTP(ctx, v)
	case "webhook", "sms":
		return sendHTTP(ctx, v)
	default:
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
}
func transportFailure(e error, written bool) Outcome {
	if errors.Is(e, ErrDenied) {
		return Outcome{State: "suppressed", Code: "permission_changed"}
	}
	var smtpError *textproto.Error
	if errors.As(e, &smtpError) {
		if smtpError.Code >= 400 && smtpError.Code < 500 {
			return Outcome{State: "retry", Code: "provider_temporary"}
		}
		return Outcome{State: "failed", Code: "provider_rejected"}
	}
	if written {
		return Outcome{State: "uncertain", Code: "receipt_unavailable"}
	}
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var name x509.HostnameError
	var cert x509.CertificateInvalidError
	if errors.As(e, &verification) || errors.As(e, &unknown) || errors.As(e, &name) || errors.As(e, &cert) {
		return Outcome{State: "failed", Code: "tls_invalid"}
	}
	return Outcome{State: "retry", Code: "connection_failed"}
}
func sendSMTP(ctx context.Context, v Outbound) Outcome {
	cfg := v.Settings.SMTP
	if !cfg.Enabled || !mailbox(v.Destination) {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	tlsConfig, e := tlsSettings(cfg.Host, cfg.CA)
	if e != nil {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if e != nil {
		return transportFailure(e, false)
	}
	defer conn.Close()
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	deadline := time.Now().Add(15 * time.Second)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	_ = conn.SetDeadline(deadline)
	if cfg.Mode == "tls" {
		secure := tls.Client(conn, tlsConfig)
		if e = secure.HandshakeContext(ctx); e != nil {
			return transportFailure(e, false)
		}
		conn = secure
	}
	c, e := smtp.NewClient(conn, cfg.Host)
	if e != nil {
		return transportFailure(e, false)
	}
	defer c.Close()
	if e = c.Hello("jumpserver233.local"); e != nil {
		return transportFailure(e, false)
	}
	if cfg.Mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return Outcome{State: "failed", Code: "tls_required"}
		}
		if e = c.StartTLS(tlsConfig); e != nil {
			return transportFailure(e, false)
		}
	}
	if e = checkOutbound(ctx, v); e != nil {
		return transportFailure(e, false)
	}
	if cfg.Username != "" {
		if e = c.Auth(smtp.PlainAuth("", cfg.Username, v.SMTPPassword, cfg.Host)); e != nil {
			return transportFailure(e, false)
		}
	}
	if e = checkOutbound(ctx, v); e != nil {
		return transportFailure(e, false)
	}
	if e = c.Mail(cfg.From); e != nil {
		return transportFailure(e, false)
	}
	if e = c.Rcpt(v.Destination); e != nil {
		return transportFailure(e, false)
	}
	if e = checkOutbound(ctx, v); e != nil {
		return transportFailure(e, false)
	}
	title, body := titleAndBody(v)
	var quoted bytes.Buffer
	q := quotedprintable.NewWriter(&quoted)
	_, _ = q.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
	_ = q.Close()
	sender := (&mail.Address{Name: "JumpServer233", Address: cfg.From}).String()
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@jumpserver233.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", sender, v.Destination, mime.QEncoding.Encode("UTF-8", strings.TrimSpace(cfg.SubjectPrefix+" "+title)), time.Now().UTC().Format(time.RFC1123Z), v.ID)
	writer, e := c.Data()
	if e != nil {
		return transportFailure(e, false)
	}
	if _, e = io.WriteString(writer, headers+quoted.String()); e != nil {
		return transportFailure(e, true)
	}
	if e = writer.Close(); e != nil {
		return transportFailure(e, true)
	}
	_ = c.Quit()
	return Outcome{State: "sent", Receipt: v.ID}
}
func sendHTTP(ctx context.Context, v Outbound) Outcome {
	cfg := v.Settings.Webhook
	if v.Channel == "sms" {
		cfg = v.Settings.SMS
	}
	if !cfg.Enabled || !validEndpoint(cfg.URL) || v.Channel == "sms" && !phonePattern.MatchString(v.Destination) {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	u, _ := url.Parse(cfg.URL)
	tlsConfig, e := tlsSettings(u.Hostname(), cfg.CA)
	if e != nil {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	title, body := titleAndBody(v)
	payload := struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organization_id"`
		UserID         string `json:"user_id"`
		Topic          string `json:"topic"`
		Title          string `json:"title"`
		Text           string `json:"text"`
		Source         Source `json:"source"`
		To             string `json:"to,omitempty"`
		Code           string `json:"code,omitempty"`
	}{ID: v.ID, OrganizationID: v.OrganizationID, UserID: v.Message.UserID, Topic: v.Message.Topic, Title: title, Text: body, Source: v.Message.Source}
	if v.Channel == "sms" {
		payload.To = v.Destination
		payload.Code = v.VerificationCode
	}
	raw, e := json.Marshal(payload)
	if e != nil || len(raw) > 16384 {
		return Outcome{State: "failed", Code: "invalid_payload"}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(raw))
	if e != nil {
		return Outcome{State: "failed", Code: "invalid_configuration"}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "jumpserver233-notifications")
	req.Header.Set("X-JMS-Notification-ID", v.ID)
	if v.HTTPBearer != "" {
		req.Header.Set("Authorization", "Bearer "+v.HTTPBearer)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("X-JMS-Timestamp", timestamp)
	if v.HTTPSecret != "" {
		mac := hmac.New(sha256.New, []byte(v.HTTPSecret))
		_, _ = io.WriteString(mac, timestamp+"\n"+v.ID+"\n")
		_, _ = mac.Write(raw)
		req.Header.Set("X-JMS-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	var wrote atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) }}))
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if e = checkOutbound(ctx, v); e != nil {
		return transportFailure(e, false)
	}
	response, e := client.Do(req)
	if e != nil {
		return transportFailure(e, wrote.Load())
	}
	defer response.Body.Close()
	if response.StatusCode == 429 {
		return Outcome{State: "retry", Code: "provider_rate_limited"}
	}
	if response.StatusCode >= 500 {
		return Outcome{State: "uncertain", Code: "provider_unavailable"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Outcome{State: "failed", Code: "provider_rejected"}
	}
	if v.Channel == "sms" {
		var receipt struct {
			Accepted bool `json:"accepted"`
		}
		d := json.NewDecoder(io.LimitReader(response.Body, 32768))
		if d.Decode(&receipt) != nil || !receipt.Accepted {
			return Outcome{State: "uncertain", Code: "receipt_unavailable"}
		}
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32768))
	}
	return Outcome{State: "sent", Receipt: v.ID}
}
