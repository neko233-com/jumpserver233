package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/neko233-com/jumpserver233/server/testsupport/notificationfixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"
)

func capture(t *testing.T, opts notificationfixture.Options) *notificationfixture.Fixture {
	t.Helper()
	f, e := notificationfixture.Start(opts)
	require.NoError(t, e)
	t.Cleanup(f.Close)
	return f
}
func outbound(f *notificationfixture.Fixture, channel string) Outbound {
	host, port, _ := net.SplitHostPort(f.SMTPAddress)
	p, _ := strconv.Atoi(port)
	return Outbound{ID: "delivery-synthetic-233", Channel: channel, Destination: "operator@jumpserver233.invalid", Language: "zh-CN", OrganizationID: "synthetic-org", SiteURL: "https://jumpserver233.invalid",
		Message:  Message{UserID: "synthetic-operator", Topic: "jobs", Name: "合成 SSH 作业", State: "succeeded", At: time.Now().UTC(), Link: "/workbench?job=synthetic", Source: Source{Kind: "jobs", ID: "synthetic", EventID: strings.Repeat("a", 64)}},
		Settings: Settings{Revision: 1, SMTP: SMTP{Enabled: true, Host: host, Port: p, Mode: "tls", From: "sender@jumpserver233.invalid", Username: "synthetic-user", CA: f.CA}, Webhook: HTTPChannel{Enabled: true, URL: f.HTTPSURL + "/webhook", CA: f.CA}, SMS: HTTPChannel{Enabled: true, URL: f.HTTPSURL + "/sms", CA: f.CA}}, SMTPPassword: "synthetic-capture-only", HTTPBearer: "synthetic-gateway-token", HTTPSecret: "synthetic-gateway-signing"}
}
func TestSMTPVerifiedTLSAndSTARTTLSMIME(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			f := capture(t, notificationfixture.Options{})
			v := outbound(f, "email")
			v.Settings.SMTP.Mode = mode
			if mode == "starttls" {
				host, port, _ := net.SplitHostPort(f.STARTTLSAddress)
				v.Settings.SMTP.Host = host
				v.Settings.SMTP.Port, _ = strconv.Atoi(port)
			}
			result := TransportSend(context.Background(), v)
			require.Equal(t, "sent", result.State, result.Code)
			rows := f.Records()
			require.Len(t, rows, 1)
			assert.True(t, rows[0].Authenticated)
			assert.Equal(t, v.ID, rows[0].ID)
			assert.Equal(t, v.Destination, rows[0].To)
			msg, e := mail.ReadMessage(strings.NewReader(rows[0].Body))
			require.NoError(t, e)
			subject, e := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			require.NoError(t, e)
			assert.Contains(t, subject, "作业结果")
			body, e := io.ReadAll(quotedprintable.NewReader(msg.Body))
			require.NoError(t, e)
			assert.Contains(t, string(body), "合成 SSH 作业")
			assert.Contains(t, string(body), "https://jumpserver233.invalid/workbench")
			assert.NotContains(t, rows[0].Body, v.SMTPPassword)
		})
	}
}
func TestSMTPRejectsUntrustedCertificateDowngradeAndUnsafeHeaders(t *testing.T) {
	f := capture(t, notificationfixture.Options{})
	v := outbound(f, "email")
	v.Settings.SMTP.CA = ""
	r := TransportSend(context.Background(), v)
	assert.Equal(t, "tls_invalid", r.Code)
	assert.Empty(t, f.Records())
	plain := capture(t, notificationfixture.Options{NoSTARTTLS: true})
	v = outbound(plain, "email")
	_, port, _ := net.SplitHostPort(plain.STARTTLSAddress)
	v.Settings.SMTP.Port, _ = strconv.Atoi(port)
	v.Settings.SMTP.Mode = "starttls"
	r = TransportSend(context.Background(), v)
	assert.Equal(t, "tls_required", r.Code)
	assert.Empty(t, plain.Records())
	for _, field := range []string{"from", "destination", "id", "prefix"} {
		t.Run(field, func(t *testing.T) {
			v := outbound(f, "email")
			switch field {
			case "from":
				v.Settings.SMTP.From += "\r\nBcc: injected@invalid"
			case "destination":
				v.Destination += "\r\nBcc: injected@invalid"
			case "id":
				v.ID += "\r\n"
			case "prefix":
				v.Settings.SMTP.SubjectPrefix = "hello\r\nBcc: invalid"
			}
			r := TransportSend(context.Background(), v)
			assert.Equal(t, "failed", r.State)
		})
	}
}
func TestProviderAcknowledgementAndUnknownSMTPOutcome(t *testing.T) {
	for _, row := range []struct {
		code int
		drop bool
		want string
	}{{250, false, "sent"}, {450, false, "retry"}, {550, false, "failed"}, {0, true, "uncertain"}} {
		t.Run(strconv.Itoa(row.code)+strconv.FormatBool(row.drop), func(t *testing.T) {
			f := capture(t, notificationfixture.Options{SMTPCode: row.code, DropSMTPReceipt: row.drop})
			r := TransportSend(context.Background(), outbound(f, "email"))
			assert.Equal(t, row.want, r.State)
			assert.Len(t, f.Records(), 1)
		})
	}
}
func TestHTTPSWebhookSignatureAndSMSContract(t *testing.T) {
	f := capture(t, notificationfixture.Options{})
	for _, channel := range []string{"webhook", "sms"} {
		v := outbound(f, channel)
		if channel == "sms" {
			v.Destination = "+15555550123"
			v.VerificationCode = "123456"
		}
		r := TransportSend(context.Background(), v)
		require.Equal(t, "sent", r.State, r.Code)
		rows := f.Records()
		record := rows[len(rows)-1]
		assert.True(t, record.Authenticated)
		mac := hmac.New(sha256.New, []byte(v.HTTPSecret))
		_, _ = io.WriteString(mac, record.Timestamp+"\n"+v.ID+"\n"+record.Body)
		assert.Equal(t, hex.EncodeToString(mac.Sum(nil)), record.Signature)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(record.Body), &payload))
		assert.Equal(t, "synthetic-org", payload["organization_id"])
		assert.Equal(t, v.Message.UserID, payload["user_id"])
		assert.NotContains(t, record.Body, v.HTTPSecret)
		assert.NotContains(t, record.Body, v.HTTPBearer)
		if channel == "sms" {
			assert.Equal(t, v.Destination, payload["to"])
			assert.Equal(t, v.VerificationCode, payload["code"])
		} else {
			assert.NotContains(t, payload, "to")
			assert.NotContains(t, payload, "code")
		}
	}
}
func TestHTTPFailureClassesAndStrictCertificates(t *testing.T) {
	for _, row := range []struct {
		code         int
		drop, reject bool
		want         string
	}{{429, false, false, "retry"}, {503, false, false, "uncertain"}, {403, false, false, "failed"}, {302, false, false, "failed"}, {0, true, false, "uncertain"}, {200, false, true, "uncertain"}} {
		t.Run(strconv.Itoa(row.code)+strconv.FormatBool(row.drop)+strconv.FormatBool(row.reject), func(t *testing.T) {
			f := capture(t, notificationfixture.Options{HTTPCode: row.code, DropHTTPReceipt: row.drop, RejectSMS: row.reject})
			v := outbound(f, "sms")
			v.Destination = "+15555550123"
			r := TransportSend(context.Background(), v)
			assert.Equal(t, row.want, r.State, r.Code)
		})
	}
	f := capture(t, notificationfixture.Options{})
	v := outbound(f, "webhook")
	v.Settings.Webhook.CA = ""
	r := TransportSend(context.Background(), v)
	assert.Equal(t, "tls_invalid", r.Code)
	assert.Empty(t, f.Records())
	v = outbound(f, "webhook")
	v.Guard = func() error { return ErrDenied }
	r = TransportSend(context.Background(), v)
	assert.Equal(t, "suppressed", r.State)
	assert.Empty(t, f.Records())
}
func TestCAAcceptsOnlyCertificatesAndLocalizedVerification(t *testing.T) {
	f := capture(t, notificationfixture.Options{})
	certs, e := parseCA(f.CA)
	require.NoError(t, e)
	assert.Len(t, certs, 1)
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")})
	for _, bad := range []string{string(block), f.CA + string(block), f.CA + "garbage", "garbage\n" + f.CA} {
		_, e := parseCA(bad)
		assert.Error(t, e)
	}
	for _, language := range []string{"en", "zh-CN"} {
		v := outbound(f, "email")
		v.Language = language
		v.VerificationCode = "123456"
		_, body := titleAndBody(v)
		assert.Contains(t, body, "123456")
		assert.NotContains(t, body, v.Message.Name)
	}
}
