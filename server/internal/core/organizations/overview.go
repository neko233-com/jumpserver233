package organizations

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

var ErrOverviewUnavailable = errors.New("organization overview unavailable")

// ResourceCounts contains aggregates only. No credentials, hostnames, commands,
// user identifiers or replay metadata cross this boundary.
type ResourceCounts struct {
	Assets         int            `json:"assets"`
	SSHAssets      int            `json:"ssh_assets"`
	Online         int            `json:"online"`
	Offline        int            `json:"offline"`
	Unknown        int            `json:"unknown"`
	Nodes          int            `json:"nodes"`
	Groups         int            `json:"groups"`
	ActiveSessions int            `json:"active_sessions"`
	ActiveJobs     int            `json:"active_jobs"`
	Protocols      map[string]int `json:"protocols"`
}
type OverviewItem struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Revision int             `json:"revision"`
	Enabled  bool            `json:"enabled"`
	Archived bool            `json:"archived"`
	Members  int             `json:"members"`
	State    string          `json:"state"`
	Counts   *ResourceCounts `json:"counts"`
}
type Overview struct {
	GeneratedAt            time.Time      `json:"generated_at"`
	Results                []OverviewItem `json:"results"`
	Totals                 ResourceCounts `json:"totals"`
	EnabledOrganizations   int            `json:"enabled_organizations"`
	CollectedOrganizations int            `json:"collected_organizations"`
	Memberships            int            `json:"memberships"`
	Partial                bool           `json:"partial"`
}

// OverviewMetadata counts active identities without exporting their names. A
// default organization exclusion overrides its implicit membership, and manual
// entries take precedence over directory-managed entries through Members.
func (s *Store) OverviewMetadata(archived bool, activeIDs []string) []OverviewItem {
	active := make(map[string]bool, len(activeIDs))
	for _, id := range activeIDs {
		active[id] = true
	}
	rows := s.List(archived)
	result := make([]OverviewItem, 0, len(rows))
	for _, org := range rows {
		members := 0
		if org.ID == DefaultID {
			members = len(active)
		}
		for _, m := range s.Members(org.ID) {
			if !active[m.UserID] {
				continue
			}
			if org.ID == DefaultID {
				if m.Role == "none" {
					members--
				}
			} else if m.Role != "none" {
				members++
			}
		}
		result = append(result, OverviewItem{ID: org.ID, Name: org.Name, Revision: org.Revision, Enabled: org.Enabled, Archived: org.ArchivedAt != nil, Members: members, State: "disabled"})
	}
	return result
}

// BuildOverview is synchronous, bounded and has no timers, cache or workers.
// Disabled/archived stores are never opened just to display totals. A failed
// collector has nil counts, so missing data cannot look like a healthy zero.
func BuildOverview(ctx context.Context, rows []OverviewItem, collect func(context.Context, string) (ResourceCounts, error), now time.Time) (Overview, error) {
	out := Overview{GeneratedAt: now.UTC(), Results: make([]OverviewItem, 0, len(rows)), Totals: ResourceCounts{Protocols: map[string]int{}}}
	if len(rows) > MaxOrganizations || collect == nil {
		return out, ErrInvalid
	}
	seen := map[string]bool{}
	for _, metadata := range rows {
		if !ValidID(metadata.ID) || seen[metadata.ID] || metadata.Members < 0 || metadata.Revision < 1 {
			return Overview{}, ErrInvalid
		}
		seen[metadata.ID] = true
		if err := ctx.Err(); err != nil {
			return Overview{}, err
		}
		row := metadata
		row.Counts = nil
		row.State = "disabled"
		out.Memberships += row.Members
		if row.Archived {
			row.State = "archived"
		} else if row.Enabled {
			out.EnabledOrganizations++
			counts, err := collect(ctx, row.ID)
			if ctx.Err() != nil {
				return Overview{}, ctx.Err()
			}
			if err != nil || !validCounts(counts) {
				row.State = "unavailable"
				out.Partial = true
			} else {
				row.State = "ready"
				row.Counts = &counts
				out.CollectedOrganizations++
				counts.Protocols = maps.Clone(counts.Protocols)
				if counts.Protocols == nil {
					counts.Protocols = map[string]int{}
				}
				addCounts(&out.Totals, counts)
			}
		}
		out.Results = append(out.Results, row)
	}
	return out, nil
}
func validCounts(v ResourceCounts) bool {
	for _, n := range []int{v.Assets, v.SSHAssets, v.Online, v.Offline, v.Unknown, v.Nodes, v.Groups, v.ActiveSessions, v.ActiveJobs} {
		if n < 0 || n > 10_000_000 {
			return false
		}
	}
	if v.SSHAssets > v.Assets || v.Online+v.Offline+v.Unknown != v.Assets || len(v.Protocols) > 20 {
		return false
	}
	total := 0
	for key, n := range v.Protocols {
		if !slices.Contains([]string{"ssh", "rdp", "telnet", "mysql", "mariadb", "postgresql", "sqlserver", "clickhouse", "redis", "mongodb", "kubernetes", "oracle", "db2", "dameng", "web", "application"}, key) || n < 0 || n > v.Assets {
			return false
		}
		total += n
	}
	return total == v.Assets
}
func addCounts(dst *ResourceCounts, v ResourceCounts) {
	dst.Assets += v.Assets
	dst.SSHAssets += v.SSHAssets
	dst.Online += v.Online
	dst.Offline += v.Offline
	dst.Unknown += v.Unknown
	dst.Nodes += v.Nodes
	dst.Groups += v.Groups
	dst.ActiveSessions += v.ActiveSessions
	dst.ActiveJobs += v.ActiveJobs
	for key, n := range v.Protocols {
		dst.Protocols[key] += n
	}
}
