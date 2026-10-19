package monitorhistory

import (
	"context"
	"time"
)

func (s *Store) Query(asset, binding string, from, to time.Time, step int) (Page, error) {
	return s.QueryContext(context.Background(), asset, binding, from, to, step)
}
func (s *Store) QueryContext(ctx context.Context, asset, binding string, from, to time.Time, step int) (Page, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return Page{}, e
	}
	if !idPattern.MatchString(asset) || !bindingPattern.MatchString(binding) || from.IsZero() || !to.After(from) || to.Sub(from) > Retention || step < 60 || step > 3600 || step%60 != 0 || int64(to.Sub(from)+time.Duration(step)*time.Second-1)/(int64(step)*int64(time.Second)) > MaxPoints {
		return Page{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Page{}, ErrClosed
	}
	now := s.now().UTC()
	if from.Before(now.Add(-Retention-time.Minute)) || to.After(now.Add(time.Minute)) {
		return Page{}, ErrInvalid
	}
	from, to = from.UTC(), to.UTC()
	width := time.Duration(step) * time.Second
	count := int((to.Sub(from) + width - 1) / width)
	page := Page{AssetID: asset, From: from, To: to, StepSeconds: step, RetentionDays: 7, Resolution: "last_sample_per_minute", Results: make([]Point, count)}
	for i := range page.Results {
		page.Results[i] = Point{At: from.Add(time.Duration(i) * width), State: "no_data", Values: map[string]Statistic{}}
	}
	for hour := from.Truncate(time.Hour); hour.Before(to); hour = hour.Add(time.Hour) {
		if e := ctx.Err(); e != nil {
			return Page{}, e
		}
		key := segmentKey(asset, hour)
		if !s.keys[key] {
			continue
		}
		v, e := s.readSegment(key, asset, hour)
		if e != nil {
			return Page{}, s.fail(e)
		}
		s.cacheSegment(key, v)
		for _, sample := range v.Samples {
			if sample.Binding != binding || sample.At.Before(from) || !sample.At.Before(to) || sample.At.Before(now.Add(-Retention)) {
				continue
			}
			p := &page.Results[int(sample.At.Sub(from)/width)]
			p.Samples++
			if sample.State == "online" {
				p.Online++
			} else {
				p.Offline++
			}
			if sample.At.After(p.LastSample) {
				p.LastSample = sample.At
			}
			for name, value := range sample.Values {
				stat := p.Values[name]
				if stat.Samples == 0 {
					stat.Min = value
					stat.Max = value
				} else {
					stat.Min = min(stat.Min, value)
					stat.Max = max(stat.Max, value)
				}
				stat.Samples++
				stat.Mean += (value - stat.Mean) / float64(stat.Samples)
				p.Values[name] = stat
			}
		}
	}
	for i := range page.Results {
		p := &page.Results[i]
		if p.Online > 0 && p.Offline > 0 {
			p.State = "mixed"
		} else if p.Online > 0 {
			p.State = "online"
		} else if p.Offline > 0 {
			p.State = "offline"
		}
	}
	page.Health = s.healthLocked()
	page.Health.Segments = 0
	prefix := assetHash(asset)
	for key := range s.keys {
		if key[:24] == prefix {
			page.Health.Segments++
		}
	}
	return page, nil
}
