package assetdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/cloudinventory"
	"github.com/neko233-com/jumpserver233/server/internal/connector/inventoryprobe"
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
)

type Gateway struct {
	Dial    inventoryprobe.DialFunc
	Close   func() error
	Current func() bool
}
type Hooks struct {
	CloudList       func(context.Context, string, cloudinventory.Config, cloudinventory.Credential) ([]cloudinventory.Instance, error)
	ApplyBatch      func(context.Context, Actor, Source, Policy, []ApplyRow) ([]ApplyResult, error)
	Authorize       func(context.Context, Actor, Source, string) error
	AuthorizeTarget func(context.Context, Actor, Source, string, int) error
	Gateway         func(context.Context, Actor, Source, string) (Gateway, error)
	Apply           func(context.Context, Actor, Source, Policy, Finding, assets.Input, bool) (string, string, error)
	Bound           func(string, string) (string, bool)
	Probe           func(context.Context, string, int, string, time.Duration, inventoryprobe.DialFunc) inventoryprobe.Result
}
type ApplyRow struct {
	Finding Finding
	Input   assets.Input
	Missing bool
}
type ApplyResult struct {
	AssetID, State string
	Err            error
}
type activeRun struct {
	Run    Run
	cancel context.CancelFunc
	reason string
}
type Service struct {
	store    *Store
	hooks    Hooks
	mu       sync.Mutex
	active   map[string]*activeRun
	owner    context.Context
	cancel   context.CancelFunc
	closed   bool
	started  bool
	wg       sync.WaitGroup
	importMu sync.Mutex
	now      func() time.Time
}

func NewService(store *Store, hooks Hooks) *Service {
	if hooks.Probe == nil {
		hooks.Probe = inventoryprobe.Probe
	}
	return &Service{store: store, hooks: hooks, active: map[string]*activeRun{}, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) Store() *Store { return s.store }
func (s *Service) Configure(h Hooks) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return ErrConflict
	}
	if h.Probe == nil {
		h.Probe = s.hooks.Probe
	}
	if h.CloudList == nil {
		h.CloudList = s.hooks.CloudList
	}
	s.hooks = h
	return nil
}
func (s *Service) authorize(ctx context.Context, a Actor, source Source, action string) error {
	if !validActor(a) || s.hooks.Authorize == nil {
		return ErrDenied
	}
	return s.hooks.Authorize(ctx, a, source, action)
}
func (s *Service) ValidateSnapshot(source string, revision int, policy string, policyRevision int) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return e
	}
	src, e := sourceFrom(s.store.data, source)
	if e != nil {
		return e
	}
	if !src.Input.Enabled || src.Input.Revision != revision {
		return ErrConflict
	}
	if policy != "" {
		p, ok := s.store.data.Policies[policy]
		if !ok || !p.Enabled || p.SourceID != source || p.Revision != policyRevision || p.SourceRevision != revision {
			return ErrConflict
		}
	}
	return nil
}
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.hooks.Authorize == nil {
		return ErrDenied
	}
	if s.started {
		return nil
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return e
	}
	next := copyJSON(s.store.data)
	changed := false
	for id, record := range next.Runs {
		if record.State == "scanning" || record.State == "syncing" || record.State == "waiting_review" {
			record.State = "interrupted"
			record.ErrorCode = "scan_runtime_stopped"
			record.Revision++
			record.FinishedAt = s.now()
			next.Runs[id] = record
			changed = true
			audit(&next, Audit{At: s.now(), Actor: record.Actor, Action: "run_interrupted", SourceID: record.SourceID, PolicyID: record.PolicyID, RunID: id})
		}
	}
	if changed {
		if e := s.store.saveLocked(next); e != nil {
			return e
		}
	}
	s.owner, s.cancel = context.WithCancel(ctx)
	s.started = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		timer := time.NewTicker(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-s.owner.Done():
				return
			case now := <-timer.C:
				s.Tick(now.UTC())
			}
		}
	}()
	return nil
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	for _, run := range s.active {
		run.reason = "scan_runtime_stopped"
		run.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Service) CancelSource(source, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range s.active {
		if run.Run.SourceID == source {
			run.reason = code
			run.cancel()
		}
	}
}
func (s *Service) Run(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.active[id]; live != nil {
		return live.Run, nil
	}
	return s.store.Run(id)
}
func (s *Service) StartRun(ctx context.Context, in RunInput, actor Actor) (Run, error) {
	return s.startRun(ctx, in, actor, "manual", time.Time{})
}
func (s *Service) startRun(ctx context.Context, in RunInput, actor Actor, trigger string, slot time.Time) (Run, error) {
	if !requestPattern.MatchString(in.RequestID) || !validID(in.SourceID, "source") || in.SourceRevision < 1 {
		return Run{}, ErrInvalid
	}
	source, e := s.store.source(in.SourceID)
	if e != nil {
		return Run{}, e
	}
	if e = s.authorize(ctx, actor, publicSource(source), "execute"); e != nil {
		return Run{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.started || s.owner.Err() != nil {
		return Run{}, ErrClosed
	}
	id := s.store.stableID("run", actor.ID, in.SourceID+"\x00"+in.RequestID)
	inputJSON, _ := json.Marshal(in)
	digest := s.store.hash(string(inputJSON))
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e = s.store.refreshLocked(); e != nil {
		return Run{}, e
	}
	if old, ok := s.store.data.Runs[id]; ok {
		if old.RequestDigest != digest {
			return Run{}, ErrConflict
		}
		if live := s.active[id]; live != nil {
			return live.Run, nil
		}
		return old.Run, nil
	}
	source, e = sourceFrom(s.store.data, in.SourceID)
	if e != nil {
		return Run{}, e
	}
	if !source.Input.Enabled || source.Input.Revision != in.SourceRevision {
		return Run{}, ErrConflict
	}
	var policy *Policy
	if in.PolicyID != "" {
		p, ok := s.store.data.Policies[in.PolicyID]
		if !ok || !p.Enabled || p.Revision != in.PolicyRevision || p.SourceID != in.SourceID || p.SourceRevision != in.SourceRevision {
			return Run{}, ErrConflict
		}
		policy = &p
		if trigger == "schedule" && (p.Owner.ID != actor.ID || !p.NextRunAt.Equal(slot)) {
			return Run{}, ErrConflict
		}
	}
	if len(s.active) >= 4 {
		return Run{}, ErrCapacity
	}
	for _, run := range s.active {
		if run.Run.SourceID == in.SourceID {
			return Run{}, ErrConflict
		}
	}
	var addresses []string
	if source.Input.Provider == "lan" {
		addresses, e = Addresses(source.Input.Targets, source.Input.Exclude)
		if e != nil {
			return Run{}, e
		}
	}
	now := s.now()
	run := Run{ID: id, Revision: 1, SourceID: source.ID, SourceRevision: source.Input.Revision, PolicyID: in.PolicyID, PolicyRevision: in.PolicyRevision, Actor: actor, Trigger: trigger, State: "scanning", Total: len(addresses) * len(source.Input.Ports), StartedAt: now, Origin: Origin(ctx)}
	run.Origin.Method = "asset_discovery"
	next := copyJSON(s.store.data)
	if len(next.Runs) >= MaxRuns {
		oldest := ""
		for key, r := range next.Runs {
			if r.State == "scanning" || r.State == "syncing" || r.State == "waiting_review" {
				continue
			}
			if oldest == "" || r.StartedAt.Before(next.Runs[oldest].StartedAt) {
				oldest = key
			}
		}
		if oldest == "" {
			return Run{}, ErrCapacity
		}
		delete(next.Runs, oldest)
	}
	next.Runs[id] = runRecord{Run: run, RequestDigest: digest}
	if trigger == "schedule" {
		p := *policy
		if p.Schedule != nil {
			p.NextRunAt, p.CalendarWatermark, e = operations.AdvanceSchedule(*p.Schedule, now, p.NextRunAt, p.CalendarWatermark)
		}
		if e != nil {
			return Run{}, e
		}
		next.Policies[p.ID] = p
	}
	audit(&next, Audit{At: now, Actor: actor, Action: "run_started", SourceID: source.ID, PolicyID: in.PolicyID, RunID: id, Revision: run.Revision})
	if e = s.store.saveLocked(next); e != nil {
		return Run{}, e
	}
	runCtx, cancel := context.WithTimeout(WithOrigin(s.owner, run.Origin), 15*time.Minute)
	s.active[id] = &activeRun{Run: run, cancel: cancel}
	s.wg.Add(1)
	go s.scan(runCtx, source, policy, run, addresses)
	return run, nil
}
func (s *Service) Cancel(ctx context.Context, id string, actor Actor) (Run, error) {
	r, e := s.Run(id)
	if e != nil {
		return Run{}, e
	}
	source, e := s.store.Source(r.SourceID)
	if e != nil {
		return Run{}, e
	}
	if e = s.authorize(ctx, actor, source, "execute"); e != nil {
		return Run{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.active[id]; live != nil {
		live.reason = "scan_cancelled"
		live.cancel()
		return live.Run, nil
	}
	return r, nil
}
func endpointID(source, protocol, host string, port int) string {
	sum := sha256.Sum256([]byte(source + "\x00" + protocol + "\x00" + net.JoinHostPort(host, strconv.Itoa(port))))
	return hex.EncodeToString(sum[:])
}
func eligible(f Finding) bool { return f.Open && (f.Protocol != "ssh" || f.SSHVerified) }

type observation struct {
	host   string
	port   int
	result inventoryprobe.Result
	cloud  *cloudinventory.Instance
}

func (s *Service) scan(ctx context.Context, source sourceRecord, policy *Policy, run Run, addresses []string) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		if live := s.active[run.ID]; live != nil {
			live.cancel()
			delete(s.active, run.ID)
		}
		s.mu.Unlock()
	}()
	public := publicSource(source)
	var cloudTargets []observation
	if source.Input.Cloud != nil {
		var e error
		cloudTargets, e = s.cloudTargets(ctx, source, run.Actor)
		if e != nil {
			s.finish(run, "failed", cloudError(e))
			return
		}
		run.Total = len(cloudTargets)
		s.updateProgress(run)
	}
	gateway := Gateway{Close: func() error { return nil }, Current: func() bool { return true }}
	if source.Input.GatewayID != "" {
		if s.hooks.Gateway == nil {
			s.finish(run, "failed", "scan_gateway_unavailable")
			return
		}
		var e error
		gateway, e = s.waitGateway(ctx, public, &run)
		if e != nil {
			code := "scan_gateway_unavailable"
			var review *ReviewRequired
			if errors.As(e, &review) {
				code = "scan_gateway_review_denied"
			}
			if ctx.Err() != nil {
				code = "scan_cancelled"
			}
			if errors.Is(e, ErrDenied) {
				code = "scan_permission_revoked"
			}
			s.finish(run, "failed", code)
			return
		}
	}
	if gateway.Close == nil || gateway.Current == nil || source.Input.GatewayID != "" && gateway.Dial == nil {
		s.finish(run, "failed", "scan_gateway_unavailable")
		return
	}
	defer gateway.Close()
	work := make(chan observation)
	results := make(chan observation, source.Input.Concurrency*2)
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	for range source.Input.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range work {
				if workerCtx.Err() != nil {
					return
				}
				if e := s.authorize(workerCtx, run.Actor, public, "execute"); e != nil {
					select {
					case results <- observation{result: inventoryprobe.Result{ErrorCode: "scan_permission_revoked"}}:
					case <-workerCtx.Done():
					}
					return
				}
				if !gateway.Current() {
					select {
					case results <- observation{result: inventoryprobe.Result{ErrorCode: "scan_gateway_changed"}}:
					case <-workerCtx.Done():
					}
					return
				}
				if s.hooks.AuthorizeTarget != nil && target.host != "" {
					if e := s.hooks.AuthorizeTarget(workerCtx, run.Actor, public, target.host, target.port); e != nil {
						select {
						case results <- observation{result: inventoryprobe.Result{ErrorCode: "scan_permission_revoked"}}:
						case <-workerCtx.Done():
						}
						return
					}
				}
				r := target.result
				if target.cloud == nil || target.host != "" && target.cloud.State == "running" && !target.cloud.Missing {
					r = s.hooks.Probe(workerCtx, target.host, target.port, source.Input.Template.Protocol, time.Duration(source.Input.TimeoutMS)*time.Millisecond, gateway.Dial)
				}
				target.result = r
				select {
				case results <- target:
				case <-workerCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(work)
		if source.Input.Cloud != nil {
			for _, target := range cloudTargets {
				select {
				case work <- target:
				case <-workerCtx.Done():
					return
				}
			}
			return
		}
		for _, host := range addresses {
			for _, port := range source.Input.Ports {
				select {
				case work <- observation{host: host, port: port}:
				case <-workerCtx.Done():
					return
				}
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	observed := []observation{}
	code := ""
	for result := range results {
		if result.result.ErrorCode == "scan_gateway_unavailable" {
			code = "scan_gateway_unavailable"
			cancel()
			continue
		}
		if result.host == "" && result.cloud == nil {
			code = result.result.ErrorCode
			cancel()
			continue
		}
		if result.result.ErrorCode == "scan_gateway_unavailable" {
			code = result.result.ErrorCode
			cancel()
		}
		observed = append(observed, result)
		run.Completed++
		if result.result.Open {
			run.Reachable++
		}
		s.mu.Lock()
		if live := s.active[run.ID]; live != nil {
			live.Run.Completed = run.Completed
			live.Run.Reachable = run.Reachable
		}
		s.mu.Unlock()
	}
	if ctx.Err() != nil || code != "" {
		s.mu.Lock()
		if live := s.active[run.ID]; live != nil && live.reason != "" {
			code = live.reason
		}
		s.mu.Unlock()
		if code == "" {
			code = "scan_timeout"
		}
		state := "failed"
		if code == "scan_cancelled" {
			state = "cancelled"
		}
		if code == "scan_runtime_stopped" {
			state = "interrupted"
		}
		s.finish(run, state, code)
		return
	}
	if e := s.ValidateSnapshot(source.ID, source.Input.Revision, run.PolicyID, run.PolicyRevision); e != nil {
		s.finish(run, "interrupted", "scan_configuration_changed")
		return
	}
	findings, e := s.publishObservations(source, run, observed)
	if e != nil {
		s.finish(run, "failed", "scan_storage_failed")
		return
	}
	run.State = "syncing"
	s.updateProgress(run)
	if policy != nil {
		pending := []Finding{}
		missingRows := []bool{}
		flush := func() error {
			if len(pending) == 0 {
				return nil
			}
			synced, e := s.applyRows(ctx, run.Actor, source, *policy, pending, missingRows)
			if e != nil {
				return e
			}
			for _, f := range synced {
				if f.SyncError != "" {
					run.Conflicts++
				}
				if f.SyncState == "created" {
					run.Imported++
				}
				if f.SyncState == "updated" || f.SyncState == "address_updated" {
					run.Updated++
				}
			}
			if e = s.saveFindingBatch(run, synced); e != nil {
				return e
			}
			s.updateProgress(run)
			pending = nil
			missingRows = nil
			return nil
		}
		for _, f := range findings {
			if ctx.Err() != nil {
				break
			}
			if !matchPolicy(*policy, f.Host) {
				continue
			}
			missing := !eligible(f) && policy.MissingAction == "disable" && f.ConsecutiveMisses >= policy.MissingThreshold && f.AssetID == assets.DiscoveryAssetID(source.ID, f.ID)
			if !eligible(f) && !missing {
				continue
			}
			bound := f.AssetID == assets.DiscoveryAssetID(source.ID, f.ID)
			if s.hooks.Bound != nil {
				ownedID, owned := s.hooks.Bound(source.ID, f.ID)
				bound = owned
				if owned {
					f.AssetID = ownedID
				}
			}
			if !bound && !policy.AutoImport {
				continue
			}
			if !bound && f.Protocol == "ssh" {
				if !policy.TrustNewSSHKeys {
					continue
				}
				if e = s.authorize(ctx, run.Actor, public, "trust"); e != nil {
					code = "scan_permission_revoked"
					break
				}
			}
			pending = append(pending, f)
			missingRows = append(missingRows, missing)
			if len(pending) == MaxImportRows {
				if e = flush(); e != nil {
					code = syncError(e)
					break
				}
			}
		}
		if code == "" && ctx.Err() == nil {
			if e = flush(); e != nil {
				code = syncError(e)
			}
		}
	}
	if ctx.Err() != nil && code == "" {
		code = "scan_cancelled"
	}
	state := "completed"
	if code != "" {
		state = "failed"
	}
	s.finish(run, state, code)
}
func (s *Service) publishObservations(source sourceRecord, run Run, observed []observation) ([]Finding, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return nil, e
	}
	current, e := sourceFrom(s.store.data, source.ID)
	if e != nil || current.Input.Revision != run.SourceRevision {
		return nil, ErrConflict
	}
	next := copyJSON(s.store.data)
	now := s.now()
	out := []Finding{}
	for _, o := range observed {
		id := endpointID(source.ID, source.Input.Template.Protocol, o.host, o.port)
		if o.cloud != nil {
			id = cloudFindingID(source.ID, source.Input.Template.Protocol, *o.cloud, o.port)
		}
		old, exists := next.Findings[id]
		if !exists && !o.result.Open && o.cloud == nil {
			continue
		}
		f := old
		f.ID = id
		f.SourceID = source.ID
		f.SourceRevision = run.SourceRevision
		f.Host = o.host
		if f.Host == "" && o.cloud != nil {
			f.Host = old.Host
		}
		f.Port = o.port
		f.Protocol = source.Input.Template.Protocol
		f.Cloud = copyJSON(o.cloud)
		f.Revision++
		f.Result = o.result
		f.LastScanned = now
		if o.result.HostKeyFingerprint == "" {
			f.HostKeyFingerprint = old.HostKeyFingerprint
		}
		if f.FirstSeen.IsZero() {
			f.FirstSeen = now
		}
		if eligible(f) || f.Cloud != nil && !f.Cloud.Missing {
			f.LastSeen = now
			f.ConsecutiveMisses = 0
		} else {
			f.ConsecutiveMisses++
		}
		if f.SyncState == "" {
			f.SyncState = "pending"
		}
		next.Findings[id] = f
		out = append(out, f)
	}
	if len(next.Findings) > MaxFindings {
		return nil, ErrCapacity
	}
	record := next.Runs[run.ID]
	record.Run = run
	record.State = "syncing"
	record.Revision++
	next.Runs[run.ID] = record
	if e = s.store.saveLocked(next); e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) apply(ctx context.Context, actor Actor, source sourceRecord, policy Policy, f Finding, missing bool) (string, string, error) {
	if s.hooks.Apply == nil {
		return "", "", ErrDenied
	}
	if e := s.ValidateSnapshot(source.ID, source.Input.Revision, policy.ID, policy.Revision); e != nil {
		return "", "", e
	}
	in := discoveryInput(source, policy, f)
	return s.hooks.Apply(ctx, actor, publicSource(source), policy, f, in, missing)
}
func (s *Service) saveFindingSync(run Run, f Finding) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return e
	}
	source, e := sourceFrom(s.store.data, run.SourceID)
	if e != nil || source.Input.Revision != run.SourceRevision {
		return ErrConflict
	}
	current, ok := s.store.data.Findings[f.ID]
	if !ok || current.Revision != f.Revision {
		return ErrConflict
	}
	next := copyJSON(s.store.data)
	f.Revision++
	next.Findings[f.ID] = f
	return s.store.saveLocked(next)
}
func (s *Service) finish(run Run, state, code string) {
	s.mu.Lock()
	if active := s.active[run.ID]; active != nil && active.reason != "" {
		code = active.reason
	}
	s.mu.Unlock()
	if code == "scan_cancelled" {
		state = "cancelled"
	}
	if code == "scan_runtime_stopped" || code == "scan_configuration_changed" {
		state = "interrupted"
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if s.store.refreshLocked() != nil {
		return
	}
	record, ok := s.store.data.Runs[run.ID]
	if !ok {
		return
	}
	next := copyJSON(s.store.data)
	run.State = state
	run.ErrorCode = code
	run.FinishedAt = s.now()
	run.Revision = record.Revision + 1
	record.Run = run
	next.Runs[run.ID] = record
	audit(&next, Audit{At: s.now(), Actor: run.Actor, Action: "run_finished", SourceID: run.SourceID, PolicyID: run.PolicyID, RunID: run.ID, Count: run.Completed})
	_ = s.store.saveLocked(next)
}
func (s *Service) Tick(now time.Time) {
	s.mu.Lock()
	owner := s.owner
	ready := s.started && !s.closed
	s.mu.Unlock()
	if !ready || owner.Err() != nil {
		return
	}
	policies, e := s.store.Policies()
	if e != nil {
		return
	}
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].NextRunAt.Equal(policies[j].NextRunAt) {
			return policies[i].ID < policies[j].ID
		}
		return policies[i].NextRunAt.Before(policies[j].NextRunAt)
	})
	for _, p := range policies {
		if !p.Enabled || p.Schedule == nil || p.NextRunAt.IsZero() || p.NextRunAt.After(now) {
			continue
		}
		source, e := s.store.Source(p.SourceID)
		if e != nil || !source.Enabled {
			continue
		}
		if p.Schedule.Kind == "cron" && p.Schedule.MisfirePolicy == "skip" && now.Sub(p.NextRunAt) > time.Duration(p.Schedule.GraceSeconds)*time.Second {
			s.skipSchedule(p, now, "schedule_missed_skipped")
			continue
		}
		s.mu.Lock()
		overlap := false
		for _, active := range s.active {
			if active.Run.SourceID == source.ID {
				overlap = true
				break
			}
		}
		s.mu.Unlock()
		if overlap {
			s.skipSchedule(p, now, "schedule_previous_run_active")
			continue
		}
		request := fmt.Sprintf("schedule-%s-%d", p.ID, p.NextRunAt.Unix())
		_, e = s.startRun(WithOrigin(owner, p.Origin), RunInput{SourceID: source.ID, SourceRevision: source.Revision, PolicyID: p.ID, PolicyRevision: p.Revision, RequestID: request}, p.Owner, "schedule", p.NextRunAt)
		if errors.Is(e, ErrDenied) {
			s.disableSchedule(p, now)
		}
	}
}
func (s *Service) disableSchedule(p Policy, now time.Time) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if s.store.refreshLocked() != nil {
		return
	}
	current, ok := s.store.data.Policies[p.ID]
	if !ok || current.Revision != p.Revision {
		return
	}
	next := copyJSON(s.store.data)
	current.Enabled = false
	current.LastScheduleError = "schedule_permission_revoked"
	current.NextRunAt = time.Time{}
	current.Revision++
	next.Policies[p.ID] = current
	audit(&next, Audit{At: now, Actor: p.Owner, Action: "schedule_permission_revoked", SourceID: p.SourceID, PolicyID: p.ID, Revision: current.Revision})
	_ = s.store.saveLocked(next)
}
func (s *Service) skipSchedule(p Policy, now time.Time, code string) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if s.store.refreshLocked() != nil {
		return
	}
	current, ok := s.store.data.Policies[p.ID]
	if !ok || current.Revision != p.Revision || !current.NextRunAt.Equal(p.NextRunAt) {
		return
	}
	next := copyJSON(s.store.data)
	at, wall, e := operations.AdvanceSchedule(*current.Schedule, now, current.NextRunAt, current.CalendarWatermark)
	if e != nil {
		return
	}
	current.NextRunAt = at
	current.CalendarWatermark = wall
	current.SkippedTriggers++
	current.LastScheduleError = code
	next.Policies[p.ID] = current
	audit(&next, Audit{At: now, Actor: p.Owner, Action: code, SourceID: p.SourceID, PolicyID: p.ID})
	_ = s.store.saveLocked(next)
}

func (s *Service) updateProgress(run Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.active[run.ID]; live != nil {
		live.Run = run
	}
}
func (s *Service) Runs(source string, offset, limit int) ([]Run, int, error) {
	rows, total, e := s.store.Runs(source, offset, limit)
	if e != nil {
		return nil, 0, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range rows {
		if live := s.active[rows[i].ID]; live != nil {
			rows[i] = live.Run
		}
	}
	return rows, total, nil
}
func (s *Service) stage(run Run) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if e := s.store.refreshLocked(); e != nil {
		return e
	}
	old, ok := s.store.data.Runs[run.ID]
	if !ok {
		return ErrNotFound
	}
	next := copyJSON(s.store.data)
	run.Revision = old.Revision + 1
	old.Run = run
	next.Runs[run.ID] = old
	return s.store.saveLocked(next)
}
func (s *Service) waitGateway(ctx context.Context, source Source, run *Run) (Gateway, error) {
	for {
		if e := s.authorize(ctx, run.Actor, source, "execute"); e != nil {
			return Gateway{}, e
		}
		if e := s.ValidateSnapshot(source.ID, source.Revision, run.PolicyID, run.PolicyRevision); e != nil {
			return Gateway{}, e
		}
		gateway, e := s.hooks.Gateway(ctx, run.Actor, source, run.ID)
		if e == nil {
			run.State = "scanning"
			s.updateProgress(*run)
			if saveError := s.stage(*run); saveError != nil {
				gateway.Close()
				return Gateway{}, saveError
			}
			return gateway, nil
		}
		var review *ReviewRequired
		if !errors.As(e, &review) {
			return Gateway{}, e
		}
		if review.State != "pending" || !review.ExpiresAt.After(s.now()) {
			return Gateway{}, e
		}
		if run.ReviewID != review.ID || run.State != "waiting_review" {
			run.State = "waiting_review"
			run.ReviewID = review.ID
			if e = s.stage(*run); e != nil {
				return Gateway{}, e
			}
			s.updateProgress(*run)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Gateway{}, ctx.Err()
		case <-timer.C:
		}
	}
}
