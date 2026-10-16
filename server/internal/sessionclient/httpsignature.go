package sessionclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c *Client) authorizeRequest(request *http.Request) error {
	if c.organization != "" {
		request.Header.Set("X-JMS-ORG", c.organization)
	}
	if c.keyID != "" {
		return signRequest(request, c.keyID, c.secret)
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	return nil
}

func signRequest(request *http.Request, keyID, secret string) error {
	if strings.TrimSpace(keyID) == "" || secret == "" {
		return fmt.Errorf("AccessKey ID and secret are required")
	}
	request.Header.Set("Accept", "application/json")
	date := time.Now().UTC().Format(http.TimeFormat)
	request.Header.Set("Date", date)
	requestTarget := strings.ToLower(request.Method) + " " + request.URL.RequestURI()
	stringToSign := "(request-target): " + requestTarget + "\naccept: application/json\ndate: " + date
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	request.Header.Set("Authorization", "Signature keyId="+strconv.Quote(keyID)+",algorithm=\"hmac-sha256\",headers=\"(request-target) accept date\",signature="+strconv.Quote(signature))
	return nil
}
