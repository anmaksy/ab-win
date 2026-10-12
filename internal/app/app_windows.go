//go:build windows

// Package app is the resolver runtime shared by the Windows service and the
// foreground `ab-win run` mode.
package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/anmaksy/ab-win/internal/api"
	"github.com/anmaksy/ab-win/internal/cache"
	"github.com/anmaksy/ab-win/internal/catalog"
	"github.com/anmaksy/ab-win/internal/config"
	"github.com/anmaksy/ab-win/internal/dnsserver"
	"github.com/anmaksy/ab-win/internal/domain"
	"github.com/anmaksy/ab-win/internal/ipc"
	"github.com/anmaksy/ab-win/internal/lists"
	"github.com/anmaksy/ab-win/internal/logfile"
	"github.com/anmaksy/ab-win/internal/netcfg"
	"github.com/anmaksy/ab-win/internal/paths"
	"github.com/anmaksy/ab-win/internal/policy"
	"github.com/anmaksy/ab-win/internal/selfupdate"
	"github.com/anmaksy/ab-win/internal/stats"
	"github.com/anmaksy/ab-win/internal/updater"
	"github.com/anmaksy/ab-win/internal/upstream"
	"github.com/anmaksy/ab-win/internal/version"

	"golang.org/x/sys/windows"
)

// Options configures a runtime.
type Options struct {
	Paths      paths.Paths
	Listen     []string // default 127.0.0.1:53 and [::1]:53
	Route      bool     // point Windows DNS at us (service mode)
	PipePrefix string   // tests only
	Console    io.Writer
}

// App is a running resolver.
type App struct {
	opt    Options
	log    *log.Logger
	logw   *logfile.Writer
	engine *policy.Engine
	dns    *dnsserver.Server
	stats  *stats.Stats
	upd    *updater.Updater
	net    *netcfg.Manager
	ipc    *ipc.Server
	http   *http.Client

	mu           sync.Mutex
	cfg          config.Config
	rt           config.Runtime
	pauseReboot  bool
	pauseTimer   *time.Timer
	latest       string // newer release tag, if any
	stopWatch    func()
	reapply      func()
	updateMu     sync.Mutex
	listsUpdated time.Time
	cancel       context.CancelFunc
}

// ErrPortInUse wraps a failure to bind port 53.
var ErrPortInUse = errors.New("port 53 is in use")

// Start brings everything up. On error nothing is left running.
func Start(opt Options) (*App, error) {
	if len(opt.Listen) == 0 {
		opt.Listen = []string{"127.0.0.1:53", "[::1]:53"}
	}
	if err := os.MkdirAll(opt.Paths.Data, 0o755); err != nil {
		return nil, err
	}
	a := &App{opt: opt, http: &http.Client{Timeout: 2 * time.Minute}}
	var out io.Writer = io.Discard
	if w, err := logfile.Open(opt.Paths.Log()); err == nil {
		a.logw, out = w, w
	}
	if opt.Console != nil {
		out = io.MultiWriter(out, opt.Console)
	}
	a.log = log.New(out, "", log.LstdFlags)

	cfg, err := config.Load(opt.Paths.Config())
	if err != nil {
		a.log.Printf("config: %v (using defaults)", err)
	}
	if _, statErr := os.Stat(opt.Paths.Config()); errors.Is(statErr, os.ErrNotExist) {
		config.Save(opt.Paths.Config(), cfg)
	}
	a.cfg = cfg
	a.rt = config.LoadRuntime(opt.Paths.Runtime())

	builtin, sentinels := updater.BuiltinAllow()
	a.engine = policy.NewEngine()
	a.engine.SetBuiltinAllow(builtin)
	a.loadUserRules()

	a.stats = stats.New(cfg.QueryLogSize, cfg.QueryLog)
	a.net = &netcfg.Manager{Path: opt.Paths.State(), ForceVPN: cfg.ForceVPN, Logf: a.log.Printf}
	a.dns = &dnsserver.Server{Engine: a.engine, Cache: cache.New(10000), Stats: a.stats, Logf: a.log.Printf}
	a.applyUpstream()
	a.dns.SetCNAMECheck(cfg.CNAMECheck)
	a.dns.SetSearchDomains(netcfg.SearchDomains())
	a.applyFiltering()

	if err := a.dns.Listen(opt.Listen); err != nil {
		a.close()
		return nil, fmt.Errorf("%w: %v", ErrPortInUse, err)
	}
	a.log.Printf("ab-win %s listening on %s", version.Version, strings.Join(opt.Listen, ", "))

	// Lists: load the compiled snapshot, or build one from seeds + cache.
	if s, err := policy.ReadFile(opt.Paths.ListsBin()); err == nil {
		a.engine.SetSnapshot(s)
		if st, err := os.Stat(opt.Paths.ListsBin()); err == nil {
			a.listsUpdated = st.ModTime()
		}
		a.log.Printf("loaded %d domains", s.Len())
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			a.log.Printf("lists.bin unreadable (%v); rebuilding", err)
		}
		a.recompile()
	}

	a.upd = &updater.Updater{Dir: opt.Paths.ListsDir(), Client: a.http, Sentinels: sentinels, Logf: a.log.Printf}

	a.ipc = &ipc.Server{Handler: a.handle, Prefix: opt.PipePrefix}
	if err := a.ipc.Start(cfg.LockSettings); err != nil {
		a.log.Printf("IPC: %v", err)
		a.dns.Shutdown()
		a.close()
		return nil, err
	}

	if opt.Route {
		// After the watchdog had to restore DNS (crash loop), wait until
		// we've been healthy for a while before taking DNS over again.
		hold := time.Duration(0)
		if _, err := os.Stat(opt.Paths.Failsafe()); err == nil {
			hold = 2 * time.Minute
			a.log.Printf("recovering from failsafe; taking over DNS in %v if stable", hold)
		}
		var routeOn atomic.Bool
		start := time.Now()
		reapply := func() {
			if time.Since(start) < hold {
				return
			}
			if !routeOn.Swap(true) {
				os.Remove(opt.Paths.Failsafe())
			}
			a.mu.Lock()
			a.net.ForceVPN = a.cfg.ForceVPN
			a.mu.Unlock()
			if _, err := a.net.Apply(); err != nil {
				a.log.Printf("routing: %v", err)
			}
			a.dns.SetSearchDomains(netcfg.SearchDomains())
		}
		a.reapply = reapply
		reapply()
		a.stopWatch = netcfg.Watch(time.Minute, reapply)
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.updateLoop(ctx)
	return a, nil
}

// Stop shuts down. With restoreDNS, Windows DNS goes back to the saved
// originals so the machine keeps working while we're not running.
func (a *App) Stop(restoreDNS bool) {
	if a.cancel != nil {
		a.cancel()
	}
	if a.stopWatch != nil {
		a.stopWatch()
	}
	if a.opt.Route && restoreDNS {
		if err := a.net.Restore(); err != nil {
			a.log.Printf("restore DNS: %v", err)
		}
	}
	a.ipc.Close()
	a.dns.Shutdown()
	a.log.Printf("stopped")
	a.close()
}

// Reapply re-checks DNS routing now (resume from sleep).
func (a *App) Reapply() {
	if a.reapply != nil {
		a.reapply()
	}
	netcfg.Flush()
}

func (a *App) close() {
	if a.logw != nil {
		a.logw.Close()
	}
}

func (a *App) systemResolver() upstream.Resolver {
	return upstream.NewPlain("network DNS", a.net.NetworkServers)
}

func (a *App) applyUpstream() {
	sys := a.systemResolver()
	a.dns.SetUpstream(upstream.ForProfile(a.cfg.Upstream, sys), sys)
}

// filtering state ------------------------------------------------------------

func (a *App) paused() bool {
	return a.pauseReboot || (!a.rt.PausedUntil.IsZero() && time.Now().Before(a.rt.PausedUntil))
}

// applyFiltering must be called with a.mu held or before concurrency starts.
func (a *App) applyFiltering() {
	on := a.rt.Enabled && !a.paused()
	if a.pauseTimer != nil {
		a.pauseTimer.Stop()
		a.pauseTimer = nil
	}
	if a.rt.Enabled && !a.pauseReboot && !a.rt.PausedUntil.IsZero() {
		if d := time.Until(a.rt.PausedUntil); d > 0 {
			a.pauseTimer = time.AfterFunc(d, func() {
				a.mu.Lock()
				a.rt.PausedUntil = time.Time{}
				config.SaveRuntime(a.opt.Paths.Runtime(), a.rt)
				a.applyFiltering()
				a.mu.Unlock()
				a.log.Printf("pause ended; protection back on")
			})
		} else {
			a.rt.PausedUntil = time.Time{}
		}
	}
	if a.dns.Filtering() != on {
		a.dns.SetFiltering(on)
		netcfg.Flush()
	}
}

func (a *App) stateName() string {
	switch {
	case !a.rt.Enabled:
		return "off"
	case a.paused():
		return "paused"
	}
	return "on"
}

// user rules ------------------------------------------------------------------

func readRules(path string) policy.RuleSet {
	r := policy.NewRuleSet()
	f, err := os.Open(path)
	if err != nil {
		return r
	}
	defer f.Close()
	lists.Parse(f, func(e lists.Entry) {
		if e.Exact {
			r.Exact[e.Domain] = true
		} else {
			r.Suffix[e.Domain] = true
		}
	})
	return r
}

func readLines(path string) []string {
	var out []string
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func (a *App) loadUserRules() {
	a.engine.SetUserRules(readRules(a.opt.Paths.Allow()), readRules(a.opt.Paths.Block()))
}

const userListHeader = "# One domain per line; each entry also covers its subdomains.\n# Edited by `ab-win allow/block` and the tray. Safe to edit by hand.\n"

// editRule adds or removes d in a user list file.
func (a *App) editRule(path, d string, add bool) (bool, error) {
	var keep []string
	found := false
	for _, l := range readLines(path) {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || t == "" {
			continue
		}
		if es := lists.ParseLine(t); len(es) == 1 && es[0].Domain == d {
			found = true
			if !add {
				continue
			}
		}
		keep = append(keep, t)
	}
	if add && !found {
		keep = append(keep, d)
	}
	sort.Strings(keep)
	body := userListHeader + strings.Join(keep, "\n") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	a.loadUserRules()
	a.dns.Cache.Flush()
	netcfg.Flush()
	return add != found, nil
}

// lists -------------------------------------------------------------------------

func (a *App) recompile() error {
	a.mu.Lock()
	preset, cats := a.cfg.Preset, maps(a.cfg.Categories)
	a.mu.Unlock()
	start := time.Now()
	s, err := updater.Compile(a.opt.Paths.ListsDir(), preset, cats)
	if err != nil {
		a.log.Printf("compile: %v", err)
		return err
	}
	if err := s.WriteFile(a.opt.Paths.ListsBin()); err != nil {
		a.log.Printf("write lists.bin: %v", err)
	}
	a.engine.SetSnapshot(s)
	// Compiling briefly needs far more memory than the result; give it back.
	debug.FreeOSMemory()
	a.mu.Lock()
	a.listsUpdated = time.Now()
	a.mu.Unlock()
	a.dns.Cache.Flush()
	netcfg.Flush()
	a.log.Printf("compiled %d domains from %d lists in %v", s.Len(), len(s.Lists), time.Since(start).Round(time.Millisecond))
	return nil
}

func maps(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (a *App) runUpdate(ctx context.Context) api.UpdateResult {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	a.mu.Lock()
	srcs := catalog.Sources(a.cfg.Preset, a.cfg.Categories)
	a.mu.Unlock()
	changed, errs := a.upd.UpdateAll(ctx, srcs)
	res := api.UpdateResult{Changed: changed}
	for _, e := range errs {
		res.Errors = append(res.Errors, e.Error())
	}
	if changed || a.engine.Snapshot().Len() == 0 {
		a.recompile()
	}
	res.Domains = a.engine.Snapshot().Len()
	return res
}

func (a *App) needsUpdate() bool {
	a.mu.Lock()
	srcs := catalog.Sources(a.cfg.Preset, a.cfg.Categories)
	every := time.Duration(a.cfg.UpdateHours) * time.Hour
	a.mu.Unlock()
	meta := a.upd.LoadMeta()
	for _, s := range srcs {
		if m, ok := meta[s.ID]; !ok || time.Since(m.Checked) > every {
			return true
		}
	}
	return false
}

func (a *App) updateLoop(ctx context.Context) {
	// Give the network a moment after boot, then check.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	lastAppCheck := time.Time{}
	for {
		if a.needsUpdate() {
			r := a.runUpdate(ctx)
			a.log.Printf("list update: changed=%v domains=%d errors=%d", r.Changed, r.Domains, len(r.Errors))
		}
		a.mu.Lock()
		check := a.cfg.CheckForAppUpdates
		a.mu.Unlock()
		if check && time.Since(lastAppCheck) > 24*time.Hour {
			lastAppCheck = time.Now()
			if rel, err := selfupdate.Latest(ctx, a.http, version.Repo); err == nil && selfupdate.Newer(rel.Tag, version.Version) {
				a.mu.Lock()
				a.latest = rel.Tag
				a.mu.Unlock()
				a.log.Printf("app update available: %s", rel.Tag)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

// IPC -----------------------------------------------------------------------------

func decode(params json.RawMessage, v any) error {
	if len(params) == 0 {
		return nil
	}
	return json.Unmarshal(params, v)
}

func (a *App) handle(method string, params json.RawMessage) (any, error) {
	switch method {
	case "version":
		return version.Version, nil
	case "status":
		return a.status(), nil
	case "on", "resume":
		a.mu.Lock()
		a.rt = config.Runtime{Enabled: true}
		a.pauseReboot = false
		a.applyFiltering()
		config.SaveRuntime(a.opt.Paths.Runtime(), a.rt)
		a.mu.Unlock()
		a.log.Printf("protection on")
		return a.status(), nil
	case "off":
		a.mu.Lock()
		a.rt = config.Runtime{Enabled: false}
		a.pauseReboot = false
		a.applyFiltering()
		config.SaveRuntime(a.opt.Paths.Runtime(), a.rt)
		a.mu.Unlock()
		a.log.Printf("protection off")
		return a.status(), nil
	case "pause":
		var p api.PauseParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.rt.Enabled = true
		if p.Duration == "reboot" || p.Duration == "restart" {
			a.pauseReboot = true
			a.rt.PausedUntil = time.Time{}
		} else {
			d, err := time.ParseDuration(p.Duration)
			if err != nil || d <= 0 || d > 7*24*time.Hour {
				a.mu.Unlock()
				return nil, fmt.Errorf("pause length %q: use something like 5m, 1h or reboot", p.Duration)
			}
			a.pauseReboot = false
			a.rt.PausedUntil = time.Now().Add(d).Truncate(time.Second)
		}
		a.applyFiltering()
		config.SaveRuntime(a.opt.Paths.Runtime(), a.rt)
		a.mu.Unlock()
		a.log.Printf("protection paused (%s)", p.Duration)
		return a.status(), nil
	case "allow", "unallow", "block", "unblock":
		var p api.DomainParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		d, ok := domain.Normalize(p.Domain)
		if !ok {
			if strings.TrimSpace(p.Domain) != "" && !strings.Contains(p.Domain, ".") && p.Force && method == "block" {
				d = strings.ToLower(strings.TrimSpace(p.Domain))
			} else {
				return nil, fmt.Errorf("%q is not a domain name (example: ads.example.com)", p.Domain)
			}
		}
		path := a.opt.Paths.Allow()
		if method == "block" || method == "unblock" {
			path = a.opt.Paths.Block()
		}
		changed, err := a.editRule(path, d, method == "allow" || method == "block")
		if err != nil {
			return nil, err
		}
		a.log.Printf("%s %s", method, d)
		return map[string]any{"domain": d, "changed": changed}, nil
	case "why":
		var p api.DomainParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		d := domain.NormalizeQuery(strings.TrimSpace(p.Domain))
		if n, ok := domain.Normalize(p.Domain); ok {
			d = n
		}
		dec := a.engine.Decide(d)
		return api.Why{Domain: d, Blocked: dec.Blocked, Reason: dec.Reason, Matched: dec.Matched, Active: a.dns.Filtering()}, nil
	case "recent":
		p := api.RecentParams{N: 50}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if p.N <= 0 || p.N > 10000 {
			p.N = 50
		}
		return a.stats.Recent(p.N, p.Blocked, p.Since), nil
	case "recent_blocked":
		return a.stats.RecentBlockedDomains(10), nil
	case "lists":
		return a.listsInfo(), nil
	case "lists_set":
		var p api.CategoryParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if _, ok := catalog.CategoryByID(p.Category); !ok {
			return nil, fmt.Errorf("unknown category %q; run `ab-win lists` to see them", p.Category)
		}
		a.mu.Lock()
		a.cfg.Categories[p.Category] = p.Enabled
		err := config.Save(a.opt.Paths.Config(), a.cfg)
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		a.recompile()
		go a.runUpdate(context.Background())
		return a.listsInfo(), nil
	case "preset":
		var p struct{ Preset string }
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		a.mu.Lock()
		old := a.cfg.Preset
		a.cfg.Preset = strings.ToLower(p.Preset)
		if err := a.cfg.Validate(); err != nil {
			a.cfg.Preset = old
			a.mu.Unlock()
			return nil, err
		}
		err := config.Save(a.opt.Paths.Config(), a.cfg)
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		a.recompile()
		go a.runUpdate(context.Background())
		return a.listsInfo(), nil
	case "update":
		ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
		defer cancel()
		return a.runUpdate(ctx), nil
	case "reload":
		return a.reload()
	case "lock":
		var p struct{ Locked bool }
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.cfg.LockSettings = p.Locked
		err := config.Save(a.opt.Paths.Config(), a.cfg)
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		// Reply first, then swap the pipe ACL (this call arrived on that pipe).
		go func() {
			time.Sleep(200 * time.Millisecond)
			if err := a.ipc.SetLocked(p.Locked); err != nil {
				a.log.Printf("IPC lock change: %v", err)
			}
		}()
		a.log.Printf("lock_settings = %v", p.Locked)
		return a.status(), nil
	case "self_update":
		var p struct{ Apply bool }
		decode(params, &p)
		return a.selfUpdate(p.Apply)
	}
	return nil, fmt.Errorf("unknown command %q", method)
}

// reload re-reads config.toml and the user lists after a hand edit.
func (a *App) reload() (any, error) {
	cfg, err := config.Load(a.opt.Paths.Config())
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	old := a.cfg
	a.cfg = cfg
	a.net.ForceVPN = cfg.ForceVPN
	a.mu.Unlock()
	a.loadUserRules()
	a.stats.Configure(cfg.QueryLogSize, cfg.QueryLog)
	a.dns.SetCNAMECheck(cfg.CNAMECheck)
	if old.Upstream != cfg.Upstream {
		a.applyUpstream()
	}
	if err := a.ipc.SetLocked(cfg.LockSettings); err != nil {
		a.log.Printf("IPC lock change: %v", err)
	}
	if old.Preset != cfg.Preset || !equalMaps(old.Categories, cfg.Categories) {
		a.recompile()
		go a.runUpdate(context.Background())
	}
	return a.status(), nil
}

func equalMaps(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (a *App) selfUpdate(apply bool) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	rel, err := selfupdate.Latest(ctx, a.http, version.Repo)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	res := api.SelfUpdate{Current: version.Version, Latest: rel.Tag, Newer: selfupdate.Newer(rel.Tag, version.Version)}
	if !apply || !res.Newer {
		return res, nil
	}
	bin, err := selfupdate.Download(ctx, a.http, rel)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err := selfupdate.Swap(exe, bin); err != nil {
		return nil, fmt.Errorf("replacing binary: %w", err)
	}
	a.log.Printf("updated binary to %s; restarting service", rel.Tag)
	res.Applied = true
	if a.opt.Route {
		// A detached helper restarts us; the service can't restart itself.
		cmd := exec.Command(exe, "restart-service")
		cmd.SysProcAttr = detached()
		cmd.Start()
	}
	return res, nil
}

func (a *App) status() api.Status {
	sum := a.stats.Summary()
	a.mu.Lock()
	s := api.Status{
		State:             a.stateName(),
		PausedUntil:       a.rt.PausedUntil,
		PausedUntilReboot: a.pauseReboot,
		Preset:            a.cfg.Preset,
		Upstream:          a.cfg.Upstream,
		Locked:            a.cfg.LockSettings,
		ListsUpdated:      a.listsUpdated,
		UpdateAvailable:   a.latest,
	}
	route := a.opt.Route
	a.mu.Unlock()
	if s.State != "paused" {
		s.PausedUntil = time.Time{}
	}
	s.BlockedToday, s.QueriesToday = sum.BlockedToday, sum.QueriesToday
	s.Domains = a.engine.Snapshot().Len()
	s.ListsReady = a.engine.Ready()
	s.Version = version.Version
	s.Routing = routingStatus(route)
	if route && !s.Routing.OK {
		s.Problems = append(s.Problems, "Windows DNS is not pointed at ab-win; run `ab-win doctor`")
	}
	if len(s.Routing.Bypassed) > 0 {
		s.Problems = append(s.Problems, "VPN is handling DNS — blocking inactive on: "+strings.Join(s.Routing.Bypassed, ", "))
	}
	return s
}

func routingStatus(managed bool) api.Routing {
	r := api.Routing{Managed: managed}
	ads, err := netcfg.Adapters()
	if err != nil {
		return r
	}
	routable := 0
	for _, ad := range ads {
		if !ad.Up || !ad.HasGateway {
			continue
		}
		if ad.PointsAtUs() {
			r.Adapters = append(r.Adapters, ad.Name)
		} else if ad.VPN {
			r.Bypassed = append(r.Bypassed, ad.Name)
			continue
		}
		routable++
	}
	r.OK = routable > 0 && len(r.Adapters) == routable
	return r
}

func (a *App) listsInfo() api.Lists {
	a.mu.Lock()
	cfg := a.cfg
	cats := maps(cfg.Categories)
	a.mu.Unlock()
	out := api.Lists{Preset: cfg.Preset, Domains: a.engine.Snapshot().Len()}
	for _, c := range catalog.Categories {
		out.Categories = append(out.Categories, api.CategoryInfo{ID: c.ID, Name: c.Name, Enabled: cats[c.ID], Warning: c.Warning})
	}
	meta := a.upd.LoadMeta()
	for _, s := range catalog.Sources(cfg.Preset, cats) {
		m := meta[s.ID]
		out.Sources = append(out.Sources, api.SourceInfo{ID: s.ID, Name: s.Name, Category: s.Category, Count: m.Count, Updated: m.Updated, LastError: m.LastError})
	}
	return out
}

func detached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}

// RouteRestore restores DNS from state.json without a running service
// (uninstall, watchdog, last resort).
func RouteRestore(p paths.Paths) error {
	m := &netcfg.Manager{Path: p.State()}
	return m.Restore()
}
