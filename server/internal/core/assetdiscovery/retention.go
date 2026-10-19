package assetdiscovery

import "encoding/json"

func snapshot(v any, present bool) json.RawMessage {
	if !present {
		return nil
	}
	raw, _ := json.Marshal(v)
	return raw
}
func jsonSize(v any) int { raw, _ := json.Marshal(v); return len(raw) }
func boundHistory(v *state) error {
	for jsonSize(v.Audit) > 4<<20 && len(v.Audit) > 0 {
		v.Audit = v.Audit[1:]
	}
	for jsonSize(v.Previews) > 4<<20 {
		oldest := ""
		for k, p := range v.Previews {
			if oldest == "" || p.ExpiresAt.Before(v.Previews[oldest].ExpiresAt) {
				oldest = k
			}
		}
		if oldest == "" {
			return ErrCapacity
		}
		delete(v.Previews, oldest)
	}
	for jsonSize(v.Receipts) > 8<<20 {
		oldest := ""
		for k, r := range v.Receipts {
			if r.Result != nil && (oldest == "" || r.At.Before(v.Receipts[oldest].At)) {
				oldest = k
			}
		}
		if oldest == "" {
			return ErrCapacity
		}
		delete(v.Receipts, oldest)
	}
	return nil
}
