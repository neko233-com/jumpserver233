package jobs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func (s *Service) inputDigest(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.inputKey)
	mac.Write([]byte("jms233/jobs/stdin/v1\x00"))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
func validJobInput(job Job, version int) bool {
	if job.InputDigest == "" {
		return true
	}
	raw, err := hex.DecodeString(job.InputDigest)
	return version >= 7 && job.PlaybookStep != nil && err == nil && len(raw) == 32 && hex.EncodeToString(raw) == job.InputDigest
}
