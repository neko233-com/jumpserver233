package replaystore

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func h256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func h1(key []byte, value string) []byte {
	h := hmac.New(sha1.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func sha256text(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
func sha1text(value string) string { h := sha1.Sum([]byte(value)); return hex.EncodeToString(h[:]) }
func canonical(headers map[string]string) (string, string) {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(k + ":" + strings.Join(strings.Fields(headers[k]), " ") + "\n")
	}
	return out.String(), strings.Join(keys, ";")
}
func encoded(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func (c *Cloud) sign(r *http.Request, key, payload string, now time.Time) {
	cfg := c.config
	stamp := now.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	switch cfg.Provider {
	case "s3":
		r.Header.Set("X-Amz-Date", stamp)
		r.Header.Set("X-Amz-Content-Sha256", payload)
		headers := map[string]string{"host": r.URL.Host, "x-amz-date": stamp, "x-amz-content-sha256": payload}
		if v := r.Header.Get("Range"); v != "" {
			headers["range"] = v
		}
		if cfg.SessionToken != "" {
			r.Header.Set("X-Amz-Security-Token", cfg.SessionToken)
			headers["x-amz-security-token"] = cfg.SessionToken
		}
		if v := r.Header.Get("If-None-Match"); v != "" {
			headers["if-none-match"] = v
		}
		head, signed := canonical(headers)
		request := r.Method + "\n" + r.URL.EscapedPath() + "\n\n" + head + "\n" + signed + "\n" + payload
		scope := day + "/" + cfg.Region + "/s3/aws4_request"
		signing := h256(h256(h256(h256([]byte("AWS4"+cfg.SecretAccessKey), day), cfg.Region), "s3"), "aws4_request")
		signature := hex.EncodeToString(h256(signing, "AWS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+sha256text(request)))
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
	case "oss":
		r.Header.Set("X-Oss-Date", stamp)
		r.Header.Set("X-Oss-Content-Sha256", "UNSIGNED-PAYLOAD")
		if cfg.SessionToken != "" {
			r.Header.Set("X-Oss-Security-Token", cfg.SessionToken)
		}
		headers := map[string]string{"host": r.URL.Host}
		for k, v := range r.Header {
			lower := strings.ToLower(k)
			if lower == "content-type" || lower == "content-md5" || strings.HasPrefix(lower, "x-oss-") {
				headers[lower] = strings.Join(v, ",")
			}
		}
		head, _ := canonical(headers)
		request := r.Method + "\n/" + cfg.Bucket + "/" + key + "\n\n" + head + "\nhost\nUNSIGNED-PAYLOAD"
		scope := day + "/" + cfg.Region + "/oss/aliyun_v4_request"
		signing := h256(h256(h256(h256([]byte("aliyun_v4"+cfg.SecretAccessKey), day), cfg.Region), "oss"), "aliyun_v4_request")
		signature := hex.EncodeToString(h256(signing, "OSS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+sha256text(request)))
		r.Header.Set("Authorization", "OSS4-HMAC-SHA256 Credential="+cfg.AccessKeyID+"/"+scope+",AdditionalHeaders=host,Signature="+signature)
	case "cos":
		if cfg.SessionToken != "" {
			r.Header.Set("X-Cos-Security-Token", cfg.SessionToken)
		}
		headers := map[string]string{"host": r.URL.Host, "content-type": r.Header.Get("Content-Type")}
		for _, name := range []string{"Date", "Content-MD5"} {
			if v := r.Header.Get(name); v != "" {
				headers[strings.ToLower(name)] = v
			}
		}
		for k, v := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-cos-") {
				headers[strings.ToLower(k)] = strings.Join(v, ",")
			}
		}
		keys := []string{}
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		values := []string{}
		for _, k := range keys {
			values = append(values, encoded(k)+"="+encoded(headers[k]))
		}
		times := strconv.FormatInt(now.Unix()-60, 10) + ";" + strconv.FormatInt(now.Unix()+600, 10)
		httpString := strings.ToLower(r.Method) + "\n" + r.URL.Path + "\n\n" + strings.Join(values, "&") + "\n"
		signKey := hex.EncodeToString(h1([]byte(cfg.SecretAccessKey), times))
		signature := hex.EncodeToString(h1([]byte(signKey), "sha1\n"+times+"\n"+sha1text(httpString)+"\n"))
		r.Header.Set("Authorization", "q-sign-algorithm=sha1&q-ak="+encoded(cfg.AccessKeyID)+"&q-sign-time="+times+"&q-key-time="+times+"&q-header-list="+strings.Join(keys, ";")+"&q-url-param-list=&q-signature="+signature)
	case "obs":
		r.Header.Set("Date", now.UTC().Format(http.TimeFormat))
		headers := map[string]string{}
		if cfg.SessionToken != "" {
			r.Header.Set("X-Obs-Security-Token", cfg.SessionToken)
			headers["x-obs-security-token"] = cfg.SessionToken
		}
		for k, v := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-obs-") {
				headers[strings.ToLower(k)] = strings.Join(v, ",")
			}
		}
		head, _ := canonical(headers)
		toSign := r.Method + "\n\n" + r.Header.Get("Content-Type") + "\n" + r.Header.Get("Date") + "\n" + head + "/" + cfg.Bucket + "/" + key
		r.Header.Set("Authorization", "OBS "+cfg.AccessKeyID+":"+base64.StdEncoding.EncodeToString(h1([]byte(cfg.SecretAccessKey), toSign)))
	}
}
