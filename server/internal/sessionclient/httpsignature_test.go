package sessionclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignRequestUsesJumpServerHTTPMessageSignature(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://jumpserver.example/api/v1/assets?name=qa", nil)
	const keyID = "ak-0123456789abcdef0123456789abcdef"
	const secret = "test-access-key-secret"
	if err := signRequest(request, keyID, secret); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Accept") != "application/json" {
		t.Fatalf("Accept = %q", request.Header.Get("Accept"))
	}
	date := request.Header.Get("Date")
	if _, err := http.ParseTime(date); err != nil {
		t.Fatalf("Date = %q: %v", date, err)
	}
	if delta := time.Since(mustParseHTTPDate(t, date)); delta < -time.Minute || delta > time.Minute {
		t.Fatalf("signed Date is outside the expected clock window: %s", delta)
	}
	stringToSign := "(request-target): get /api/v1/assets?name=qa\naccept: application/json\ndate: " + date
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(stringToSign))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	authorization := request.Header.Get("Authorization")
	for _, field := range []string{`keyId="` + keyID + `"`, `algorithm="hmac-sha256"`, `headers="(request-target) accept date"`, `signature="` + expected + `"`} {
		if !strings.Contains(authorization, field) {
			t.Errorf("Authorization %q does not contain %q", authorization, field)
		}
	}
}

func mustParseHTTPDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := http.ParseTime(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
