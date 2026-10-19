package main

func (r *organizationRuntimes) activity() map[string]int {
	r.mu.Lock()
	items := make([]*organizationRuntime, 0, len(r.items))
	for _, item := range r.items {
		items = append(items, item)
	}
	r.mu.Unlock()
	counts := map[string]int{}
	for _, item := range items {
		d := item.d
		if d.Sessions != nil {
			counts["terminal_sessions"] += d.Sessions.ActiveCount()
		}
		if d.Desktops != nil {
			counts["desktop_sessions"] += d.Desktops.ActiveCount()
		}
		if d.Jobs != nil {
			counts["running_jobs"] += d.Jobs.ActiveCount()
		}
		if d.DatabaseQueries != nil {
			counts["database_queries"] += d.DatabaseQueries.ActiveCount()
		}
	}
	return counts
}
