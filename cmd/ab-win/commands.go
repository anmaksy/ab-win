//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/anmaksy/ab-win/internal/api"
	"github.com/anmaksy/ab-win/internal/app"
	"github.com/anmaksy/ab-win/internal/browsers"
	"github.com/anmaksy/ab-win/internal/catalog"
	"github.com/anmaksy/ab-win/internal/doctor"
	"github.com/anmaksy/ab-win/internal/domain"
	"github.com/anmaksy/ab-win/internal/elevate"
	"github.com/anmaksy/ab-win/internal/ipc"
	"github.com/anmaksy/ab-win/internal/paths"
	"github.com/anmaksy/ab-win/internal/tray"
	"github.com/anmaksy/ab-win/internal/ui"
	"github.com/anmaksy/ab-win/internal/updater"
	"github.com/anmaksy/ab-win/internal/version"
	"github.com/anmaksy/ab-win/internal/winsvc"
)

type command struct {
	usage   string
	summary string
	help    string
	hidden  bool
	run     func(*cli) int
}

var commands map[string]command

// order is how `help` lists commands: most common first.
var order = []string{
	"status", "on", "off", "pause", "resume", "",
	"allow", "block", "unallow", "unblock", "why", "recent", "",
	"lists", "preset", "update", "",
	"install", "uninstall", "lock", "doctor", "harden-browsers", "self-update", "reload", "tray", "run", "version", "help",
}

func init() {
	commands = map[string]command{
		"status": {"status [--json]", "Is protection on? How much was blocked today?", "", false, cmdStatus},
		"on":     {"on", "Turn protection on", "", false, simple("on")},
		"off":    {"off", "Turn protection off (until you turn it on again)", "Tip: `ab-win pause` turns protection back on by itself.", false, cmdOff},
		"pause": {"pause [5m|15m|1h|reboot]", "Turn protection off for a while; it comes back on by itself (default 15m)",
			"Examples:\n  ab-win pause          # 15 minutes\n  ab-win pause 1h\n  ab-win pause reboot   # until the PC restarts", false, cmdPause},
		"resume": {"resume", "End a pause now", "", false, simple("resume")},
		"allow": {"allow <domain>", "Never block this domain (and its subdomains)",
			"Use this when a site is broken. Find the domain with `ab-win recent --blocked`.\nExample:\n  ab-win allow cdn.example.com", false, domainCmd("allow")},
		"unallow": {"unallow <domain>", "Remove a domain from your allowlist", "", false, domainCmd("unallow")},
		"block":   {"block <domain> [--yes]", "Always block this domain (and its subdomains)", "Very broad entries (a whole top-level domain or a major site) ask for confirmation.", false, domainCmd("block")},
		"unblock": {"unblock <domain>", "Remove a domain from your blocklist", "", false, domainCmd("unblock")},
		"why":     {"why <domain> [--json]", "Explain whether a domain is blocked, and by which list", "", false, cmdWhy},
		"recent": {"recent [--blocked] [-f] [-n 50] [--json]", "Show recent lookups (-f keeps following)",
			"Examples:\n  ab-win recent --blocked     # what was blocked lately\n  ab-win recent -f            # live view, Ctrl+C to stop", false, cmdRecent},
		"lists": {"lists [enable|disable <category>] [--json]", "Show block categories and lists, or switch a category",
			"Categories: ads, trackers, malware, telemetry, doh_bypass.\nExample:\n  ab-win lists enable telemetry", false, cmdLists},
		"preset": {"preset relaxed|balanced|aggressive", "Choose how strict blocking is (default: balanced)", "", false, cmdPreset},
		"update": {"update", "Download fresh blocklists now", "", false, cmdUpdate},
		"install": {"install", "Install the service, turn protection on and start it with Windows",
			"Asks for administrator approval once. Safe to run again to repair or upgrade.", false, cmdInstall},
		"uninstall": {"uninstall [--keep-data]", "Remove ab-win and restore your original DNS settings", "", false, cmdUninstall},
		"lock": {"lock on|off", "Only administrators may turn protection off or change rules (for a kid's PC)",
			"Run it from your (administrator) account. Other users then see \"Managed by administrator\" in the tray.", false, cmdLock},
		"doctor": {"doctor [--json]", "Find out why blocking isn't working", "", false, cmdDoctor},
		"harden-browsers": {"harden-browsers [--undo] [--yes]", "Stop browsers from bypassing ab-win with their own secure DNS",
			"Sets machine policies for Chrome, Edge, Brave and Firefox. Those browsers then show\n\"Managed by your organization\". Undo with --undo.", false, cmdHarden},
		"self-update": {"self-update [--check]", "Install the newest ab-win release", "", false, cmdSelfUpdate},
		"reload":      {"reload", "Re-read config.toml and your lists after editing them by hand", "", false, cmdReload},
		"tray":        {"tray", "Start the tray icon", "", false, func(*cli) int { tray.Run(); return exitOK }},
		"run": {"run [--listen 127.0.0.1:53] [--data DIR] [--route]", "Run the resolver in this terminal (for testing)",
			"Without --route, Windows DNS is not changed: point a tool at the listener, e.g.\n  nslookup doubleclick.net 127.0.0.1", false, cmdRun},
		"version": {"version", "Show the version", "", false, cmdVersion},
		"help":    {"help [command]", "Show help", "", false, cmdHelp},

		"service":         {hidden: true, run: func(*cli) int { winsvc.RunService(); return exitOK }},
		"watchdog":        {hidden: true, run: func(*cli) int { winsvc.Watchdog(); return exitOK }},
		"restart-service": {hidden: true, run: cmdRestartService},
		"list-health":     {hidden: true, run: cmdListHealth},
		"unpause":         {hidden: true, run: simple("resume")},
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(out, string(b))
}

func call(method string, params, result any) error {
	return (ipc.Client{}).Call(method, params, result)
}

// --- status -----------------------------------------------------------------

func cmdStatus(c *cli) int {
	var st api.Status
	if err := call("status", nil, &st); err != nil {
		if jsonOut {
			printJSON(map[string]any{"state": "not_running", "installed": winsvc.Installed()})
		}
		return serviceErr(err)
	}
	if jsonOut {
		printJSON(st)
		return exitOK
	}
	printStatusLine(st)
	fmt.Fprintf(out, "  Lists:    %s preset, %s domains, updated %s\n", titleCase(st.Preset), thousands(st.Domains), ago(st.ListsUpdated))
	if st.Routing.Managed {
		if len(st.Routing.Adapters) > 0 {
			fmt.Fprintf(out, "  Network:  %s → ab-win\n", strings.Join(st.Routing.Adapters, ", "))
		}
	} else {
		fmt.Fprintln(out, "  Network:  not managed (ab-win run without --route)")
	}
	fmt.Fprintf(out, "  Upstream: %s\n", st.Upstream)
	if st.Locked {
		fmt.Fprintln(out, "  Settings: managed by administrator")
	}
	for _, p := range st.Problems {
		fmt.Fprintf(out, "%s %s\n", sym("warn"), p)
	}
	if st.UpdateAvailable != "" {
		fmt.Fprintf(out, "%s ab-win %s is available: run `ab-win self-update`\n", sym("warn"), st.UpdateAvailable)
	}
	return exitOK
}

func printStatusLine(st api.Status) {
	counts := fmt.Sprintf("%s blocked today (%s lookups)", thousands(st.BlockedToday), thousands(st.QueriesToday))
	switch st.State {
	case "on":
		fmt.Fprintf(out, "%s %s — %s\n", sym("ok"), bold("Protected"), counts)
	case "paused":
		until := "until the PC restarts"
		if !st.PausedUntil.IsZero() {
			until = fmt.Sprintf("resumes at %s (in %s)", st.PausedUntil.Local().Format("15:04"), humanDur(time.Until(st.PausedUntil)))
		}
		fmt.Fprintf(out, "%s %s — %s\n", sym("warn"), bold("Protection paused"), until)
	default:
		fmt.Fprintf(out, "%s %s — run `ab-win on` to turn it back on\n", sym("fail"), bold("Protection off"))
	}
}

func simple(method string) func(*cli) int {
	return func(c *cli) int {
		var st api.Status
		if err := call(method, nil, &st); err != nil {
			return serviceErr(err)
		}
		if jsonOut {
			printJSON(st)
		} else {
			printStatusLine(st)
		}
		return exitOK
	}
}

func cmdOff(c *cli) int {
	code := simple("off")(c)
	if code == exitOK && !jsonOut {
		// Hint once that pause is usually what people want.
		marker := filepath.Join(os.Getenv("LOCALAPPDATA"), "ab-win", "hinted-off")
		if _, err := os.Stat(marker); err != nil {
			fmt.Fprintln(out, dim("Tip: `ab-win pause 1h` turns protection back on by itself, so you can't forget."))
			os.MkdirAll(filepath.Dir(marker), 0o755)
			os.WriteFile(marker, nil, 0o644)
		}
	}
	return code
}

func cmdPause(c *cli) int {
	d := strings.ToLower(c.arg(0))
	switch d {
	case "":
		d = "15m"
	case "restart":
		d = "reboot"
	}
	if d != "reboot" {
		if _, err := time.ParseDuration(d); err != nil {
			fmt.Fprintf(errOut, "%q isn't a pause length. Use for example 5m, 1h or reboot.\n", d)
			return exitError
		}
	}
	var st api.Status
	if err := call("pause", api.PauseParams{Duration: d}, &st); err != nil {
		return serviceErr(err)
	}
	if jsonOut {
		printJSON(st)
	} else {
		printStatusLine(st)
	}
	return exitOK
}

// --- domains --------------------------------------------------------------------

// broad are domains so central that blocking them is almost certainly a typo.
var broad = map[string]bool{
	"google.com": true, "youtube.com": true, "facebook.com": true, "microsoft.com": true, "apple.com": true,
	"amazon.com": true, "github.com": true, "cloudflare.com": true, "akamaized.net": true, "akamaihd.net": true,
	"windows.net": true, "windows.com": true, "live.com": true, "office.com": true, "gstatic.com": true,
	"googleapis.com": true, "cloudfront.net": true, "amazonaws.com": true, "azureedge.net": true,
	"fastly.net": true, "wikipedia.org": true, "whatsapp.net": true, "icloud.com": true, "netflix.com": true,
	"co.uk": true, "com.au": true, "github.io": true,
}

func domainCmd(method string) func(*cli) int {
	return func(c *cli) int {
		raw := c.arg(0)
		if raw == "" {
			fmt.Fprintf(errOut, "Which domain? Example: ab-win %s ads.example.com\n", method)
			return exitError
		}
		raw = cleanDomainArg(raw)
		force := false
		if method == "block" {
			d, ok := domain.Normalize(raw)
			isTLD := !ok && !strings.Contains(raw, ".")
			if isTLD || broad[d] {
				what := "every site under ." + strings.ToLower(raw)
				if !isTLD {
					what = d + " and all its subdomains, which many sites and apps depend on"
				}
				if !c.has("--yes", "-y") && !confirm(fmt.Sprintf("This blocks %s. Are you sure?", what)) {
					fmt.Fprintln(out, "Nothing changed.")
					return exitError
				}
				force = true
			}
		}
		var res struct {
			Domain  string `json:"domain"`
			Changed bool   `json:"changed"`
		}
		if err := call(method, api.DomainParams{Domain: raw, Force: force}, &res); err != nil {
			return serviceErr(err)
		}
		if jsonOut {
			printJSON(res)
			return exitOK
		}
		msgs := map[string][2]string{
			"allow":   {"%s will never be blocked (subdomains too). Reload the page.", "%s was already on your allowlist."},
			"unallow": {"%s removed from your allowlist.", "%s wasn't on your allowlist."},
			"block":   {"%s is now always blocked (subdomains too).", "%s was already on your blocklist."},
			"unblock": {"%s removed from your blocklist.", "%s wasn't on your blocklist."},
		}[method]
		if res.Changed {
			fmt.Fprintf(out, "%s "+msgs[0]+"\n", sym("ok"), res.Domain)
		} else {
			fmt.Fprintf(out, "%s "+msgs[1]+"\n", sym("warn"), res.Domain)
		}
		return exitOK
	}
}

// cleanDomainArg accepts a pasted URL as well as a bare domain.
func cleanDomainArg(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, "]") {
		s = h
	}
	return s
}

func confirm(q string) bool {
	if !fancy {
		fmt.Fprintln(errOut, q+" Add --yes to confirm.")
		return false
	}
	fmt.Fprintf(out, "%s %s [y/N] ", sym("warn"), q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

func cmdWhy(c *cli) int {
	if c.arg(0) == "" {
		fmt.Fprintln(errOut, "Which domain? Example: ab-win why ads.example.com")
		return exitError
	}
	var w api.Why
	if err := call("why", api.DomainParams{Domain: cleanDomainArg(c.arg(0))}, &w); err != nil {
		return serviceErr(err)
	}
	if jsonOut {
		printJSON(w)
		return exitOK
	}
	switch {
	case w.Blocked:
		rule := ""
		if w.Matched != w.Domain {
			rule = fmt.Sprintf(" (matched %s)", w.Matched)
		}
		fmt.Fprintf(out, "%s %s is blocked by: %s%s\n", sym("fail"), bold(w.Domain), w.Reason, rule)
		fmt.Fprintf(out, "  To allow it: ab-win allow %s\n", w.Matched)
	case w.Reason != "":
		fmt.Fprintf(out, "%s %s is allowed by %s (%s)\n", sym("ok"), bold(w.Domain), w.Reason, w.Matched)
	default:
		fmt.Fprintf(out, "%s %s is allowed: it isn't on any blocklist\n", sym("ok"), bold(w.Domain))
	}
	if w.Blocked && !w.Active {
		fmt.Fprintln(out, dim("  Protection is off or paused right now, so nothing is being blocked."))
	}
	return exitOK
}

func cmdRecent(c *cli) int {
	n := 50
	fmt.Sscan(c.flag("-n", "50"), &n)
	p := api.RecentParams{N: n, Blocked: c.has("--blocked", "-b")}
	follow := c.has("-f", "--follow")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	first := true
	for {
		var qs []api.QueryEntry
		if err := call("recent", p, &qs); err != nil {
			return serviceErr(err)
		}
		if jsonOut {
			for _, q := range qs {
				b, _ := json.Marshal(q)
				fmt.Fprintln(out, string(b))
			}
		} else {
			if first && len(qs) == 0 && !follow {
				fmt.Fprintln(out, "Nothing yet. (The query log may be off: query_log in config.toml.)")
			}
			for _, q := range qs {
				mark := "  "
				if !fancy {
					mark = "ALLOWED"
				}
				if q.Blocked {
					mark = sym("blocked")
				}
				fmt.Fprintf(tw, "%s\t%s %s\t%s\t%s\n", q.Time.Local().Format("15:04:05"), mark, q.Name, q.Type, q.Reason)
			}
			tw.Flush()
		}
		for _, q := range qs {
			if q.Seq > p.Since {
				p.Since = q.Seq
			}
		}
		if !follow {
			return exitOK
		}
		if first {
			p.N = 1000
			first = false
		}
		time.Sleep(time.Second)
	}
}

// --- lists ------------------------------------------------------------------------

func cmdLists(c *cli) int {
	if verb := c.arg(0); verb == "enable" || verb == "disable" {
		cat := c.arg(1)
		if cat == "" {
			fmt.Fprintf(errOut, "Which category? Example: ab-win lists %s telemetry\n", verb)
			return exitError
		}
		if info, ok := catalog.CategoryByID(cat); ok && verb == "enable" && info.Warning != "" && !jsonOut {
			fmt.Fprintf(out, "%s %s\n", sym("warn"), info.Warning)
		}
		var l api.Lists
		if err := call("lists_set", api.CategoryParams{Category: cat, Enabled: verb == "enable"}, &l); err != nil {
			return serviceErr(err)
		}
		if !jsonOut {
			fmt.Fprintf(out, "%s %s %sd. Downloading its lists in the background.\n", sym("ok"), cat, verb)
		}
		return printLists(l)
	} else if verb != "" {
		fmt.Fprintln(errOut, "Use: ab-win lists, ab-win lists enable <category>, ab-win lists disable <category>")
		return exitError
	}
	var l api.Lists
	if err := call("lists", nil, &l); err != nil {
		return serviceErr(err)
	}
	return printLists(l)
}

func printLists(l api.Lists) int {
	if jsonOut {
		printJSON(l)
		return exitOK
	}
	fmt.Fprintf(out, "Preset: %s — %s domains blocked\n\n", bold(titleCase(l.Preset)), thousands(l.Domains))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tID\tON")
	for _, ct := range l.Categories {
		on := "no"
		if ct.Enabled {
			on = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", ct.Name, ct.ID, on)
	}
	tw.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(tw, "DOWNLOADED LIST\tDOMAINS\tUPDATED")
	for _, s := range l.Sources {
		upd := ago(s.Updated)
		if s.LastError != "" {
			upd += " (last try failed: " + s.LastError + ")"
		}
		count := thousands(s.Count)
		if s.Count == 0 {
			count = "–"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, count, upd)
	}
	tw.Flush()
	fmt.Fprintln(out, dim("\nBuilt-in seed lists are always included for enabled categories."))
	return exitOK
}

func cmdPreset(c *cli) int {
	p := strings.ToLower(c.arg(0))
	if p == "" {
		fmt.Fprintln(errOut, "Use: ab-win preset relaxed|balanced|aggressive")
		return exitError
	}
	var l api.Lists
	if err := call("preset", map[string]string{"preset": p}, &l); err != nil {
		return serviceErr(err)
	}
	if !jsonOut {
		fmt.Fprintf(out, "%s Preset set to %s. Downloading its lists in the background.\n", sym("ok"), titleCase(p))
	}
	return printLists(l)
}

func cmdUpdate(c *cli) int {
	if !jsonOut {
		fmt.Fprintln(out, "Downloading lists…")
	}
	var r api.UpdateResult
	if err := (ipc.Client{Timeout: 5 * time.Second}).Call("update", nil, &r); err != nil {
		return serviceErr(err)
	}
	if jsonOut {
		printJSON(r)
		return exitOK
	}
	if r.Changed {
		fmt.Fprintf(out, "%s Lists updated — %s domains blocked\n", sym("ok"), thousands(r.Domains))
	} else {
		fmt.Fprintf(out, "%s Lists are already up to date — %s domains blocked\n", sym("ok"), thousands(r.Domains))
	}
	for _, e := range r.Errors {
		fmt.Fprintf(out, "%s %s (kept the last good copy)\n", sym("warn"), e)
	}
	return exitOK
}

func cmdReload(c *cli) int {
	var st api.Status
	if err := call("reload", nil, &st); err != nil {
		return serviceErr(err)
	}
	fmt.Fprintf(out, "%s Settings reloaded\n", sym("ok"))
	return exitOK
}

// --- install & friends --------------------------------------------------------------

func cmdInstall(c *cli) int {
	if !elevate.IsAdmin() {
		code := elevated([]string{"install"})
		if code == exitOK {
			startTray()
		}
		return code
	}
	fmt.Fprintln(out, "Installing ab-win…")
	if err := winsvc.Install(out); err != nil {
		fmt.Fprintf(out, "%s Install failed: %v\n", sym("fail"), err)
		return exitError
	}
	// Wait for the service to answer and confirm DNS routing.
	var st api.Status
	for i := 0; i < 20; i++ {
		if call("status", nil, &st) == nil && (st.Routing.OK || i > 10) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(out, "%s ab-win is installed and protection is on.\n", sym("ok"))
	fmt.Fprintln(out, "  It starts with Windows. Look for the shield icon near the clock.")
	fmt.Fprintln(out, "  A site broken? Tray icon › Recently blocked › Allow.")
	if !st.Routing.OK && len(st.Problems) > 0 {
		fmt.Fprintf(out, "%s %s\n", sym("warn"), st.Problems[0])
	}
	if c.flag("--elevated-output", "") == "" && !c.has("--quiet") {
		startTray()
	}
	return exitOK
}

func startTray() {
	exe := paths.InstalledExe()
	if _, err := os.Stat(exe); err != nil {
		return
	}
	exec.Command(exe, "tray").Start()
}

func cmdUninstall(c *cli) int {
	gui := ui.OwnConsole() && c.flag("--elevated-output", "") == ""
	if !elevate.IsAdmin() {
		args := []string{"uninstall"}
		if c.has("--keep-data") {
			args = append(args, "--keep-data")
		}
		code := elevated(args)
		if gui {
			if code == exitOK {
				ui.Info("ab-win", "ab-win was removed and your original DNS settings are back.")
			} else if code != exitNeedsAdmin {
				ui.Error("ab-win", "Uninstall finished with problems. If the internet doesn't work, run restore-dns.ps1 from the ab-win GitHub page.")
			}
		}
		return code
	}
	if err := winsvc.Uninstall(winsvc.UninstallOptions{KeepData: c.has("--keep-data"), Out: out}); err != nil {
		fmt.Fprintf(out, "%s Uninstall finished with problems: %v\n", sym("warn"), err)
		return exitError
	}
	// Undo browser policies too; we keep their backup outside the data dir
	// only while installed, so do it before data removal next time.
	fmt.Fprintf(out, "%s ab-win removed. Your original DNS settings are back.\n", sym("ok"))
	return exitOK
}

func cmdLock(c *cli) int {
	v := strings.ToLower(c.arg(0))
	if v != "on" && v != "off" {
		fmt.Fprintln(errOut, "Use: ab-win lock on   or   ab-win lock off")
		return exitError
	}
	if !elevate.IsAdmin() {
		return elevated([]string{"lock", v})
	}
	var st api.Status
	if err := call("lock", map[string]bool{"locked": v == "on"}, &st); err != nil {
		return serviceErr(err)
	}
	if v == "on" {
		fmt.Fprintln(out, sym("ok"), "Settings locked. Only administrators can turn protection off or change rules now.")
	} else {
		fmt.Fprintln(out, sym("ok"), "Settings unlocked. Every user can pause, turn off and allow sites again.")
	}
	return exitOK
}

func cmdDoctor(c *cli) int {
	checks := doctor.Run()
	if jsonOut {
		printJSON(checks)
	}
	worst := exitOK
	for _, ch := range checks {
		if ch.Level == doctor.Fail {
			worst = exitError
		}
		if jsonOut {
			continue
		}
		kind := map[doctor.Level]string{doctor.OK: "ok", doctor.Warn: "warn", doctor.Fail: "fail", doctor.Info: "info"}[ch.Level]
		fmt.Fprintf(out, "%s %s: %s\n", sym(kind), bold(ch.Name), ch.Detail)
		if ch.Fix != "" {
			fmt.Fprintf(out, "    → %s\n", ch.Fix)
		}
	}
	if !jsonOut && worst == exitOK {
		fmt.Fprintln(out, "\nNo blocking problems found.")
	}
	return worst
}

func cmdHarden(c *cli) int {
	p := paths.Default().Browsers()
	undo := c.has("--undo")
	if !elevate.IsAdmin() {
		if !undo && !c.has("--yes", "-y") {
			fmt.Fprintln(out, "This stops Chrome, Edge, Brave and Firefox from using their own secure DNS, which")
			fmt.Fprintln(out, "would bypass ab-win. It sets a machine policy, so those browsers will show")
			fmt.Fprintln(out, "\"Managed by your organization\". Undo any time with `ab-win harden-browsers --undo`.")
			if !confirm("Apply the browser policies?") {
				fmt.Fprintln(out, "Nothing changed.")
				return exitError
			}
		}
		args := []string{"harden-browsers"}
		if undo {
			args = append(args, "--undo")
		}
		return elevated(args)
	}
	if undo {
		if err := browsers.Undo(p); err != nil {
			fmt.Fprintf(out, "%s %v\n", sym("fail"), err)
			return exitError
		}
		fmt.Fprintf(out, "%s Browser policies removed. Restart your browsers.\n", sym("ok"))
		return exitOK
	}
	if err := browsers.Harden(p); err != nil {
		fmt.Fprintf(out, "%s %v\n", sym("fail"), err)
		return exitError
	}
	fmt.Fprintf(out, "%s Browsers now use Windows DNS (and ab-win). Restart your browsers.\n", sym("ok"))
	return exitOK
}

func cmdSelfUpdate(c *cli) int {
	var r api.SelfUpdate
	cl := ipc.Client{Timeout: 5 * time.Second}
	if err := cl.Call("self_update", map[string]bool{"apply": !c.has("--check")}, &r); err != nil {
		return serviceErr(err)
	}
	if jsonOut {
		printJSON(r)
		return exitOK
	}
	switch {
	case !r.Newer:
		fmt.Fprintf(out, "%s You have the newest version (%s).\n", sym("ok"), r.Current)
	case r.Applied:
		fmt.Fprintf(out, "%s Updated %s → %s. The service is restarting.\n", sym("ok"), r.Current, r.Latest)
	default:
		fmt.Fprintf(out, "%s %s is available (you have %s). Run `ab-win self-update` to install it.\n", sym("warn"), r.Latest, r.Current)
	}
	return exitOK
}

func cmdRestartService(c *cli) int {
	time.Sleep(time.Second)
	if err := winsvc.Restart(); err != nil {
		return exitError
	}
	return exitOK
}

func cmdRun(c *cli) int {
	p := paths.Default()
	if d := c.flag("--data", ""); d != "" {
		p = paths.Paths{Data: d}
	}
	listen := []string{"127.0.0.1:53", "[::1]:53"}
	if l := c.flag("--listen", ""); l != "" {
		listen = strings.Split(l, ",")
	}
	route := c.has("--route")
	if route && !elevate.IsAdmin() {
		fmt.Fprintln(errOut, "--route changes Windows DNS settings and needs an administrator terminal.")
		return exitNeedsAdmin
	}
	a, err := app.Start(app.Options{Paths: p, Listen: listen, Route: route, Console: out})
	if err != nil {
		fmt.Fprintln(errOut, "Could not start:", err)
		if strings.Contains(err.Error(), "port 53") {
			if perr := winsvc.CheckPort53(); perr != nil {
				fmt.Fprintln(errOut, perr)
			}
		}
		return exitError
	}
	fmt.Fprintf(out, "%s Resolver running on %s. Press Ctrl+C to stop.\n", sym("ok"), strings.Join(listen, ", "))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	a.Stop(true)
	return exitOK
}

func cmdListHealth(c *cli) int {
	results := updater.Health(context.Background(), &http.Client{Timeout: 3 * time.Minute}, catalog.AllSources())
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	if jsonOut {
		printJSON(results)
	}
	bad := 0
	for _, r := range results {
		if r.Error != "" {
			bad++
		}
		if !jsonOut {
			status := fmt.Sprintf("OK %d", r.Count)
			if r.Error != "" {
				status = "FAIL " + r.Error
			}
			fmt.Fprintf(out, "%-18s %s  %s\n", r.ID, status, r.URL)
		}
	}
	if bad > 0 {
		return exitError
	}
	return exitOK
}

func cmdVersion(c *cli) int {
	fmt.Fprintf(out, "ab-win %s\n", version.Version)
	return exitOK
}

func cmdHelp(c *cli) int {
	if name := c.arg(0); name != "" {
		cmd, ok := commands[name]
		if !ok || cmd.hidden {
			fmt.Fprintf(errOut, "No command %q. Run `ab-win help`.\n", name)
			return exitError
		}
		fmt.Fprintf(out, "Usage: ab-win %s\n\n%s\n", cmd.usage, cmd.summary)
		if cmd.help != "" {
			fmt.Fprintf(out, "\n%s\n", cmd.help)
		}
		return exitOK
	}
	fmt.Fprintf(out, "ab-win %s — blocks ads, trackers and malware for every app on this PC.\n\n", version.Version)
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for _, name := range order {
		if name == "" {
			fmt.Fprintln(tw, "\t")
			continue
		}
		cmd := commands[name]
		fmt.Fprintf(tw, "  %s\t%s\n", cmd.usage, cmd.summary)
	}
	tw.Flush()
	fmt.Fprintln(out, "\nRead commands accept --json. Run `ab-win help <command>` for examples.")
	return exitOK
}

// doubleClick handles ab-win.exe started from Explorer with no arguments.
func doubleClick() int {
	if winsvc.Installed() {
		ui.HideConsole()
		exe := paths.InstalledExe()
		if _, err := os.Stat(exe); err != nil {
			exe, _ = os.Executable()
		}
		exec.Command(exe, "tray").Start()
		ui.Info("ab-win", "ab-win is already installed. Use the shield icon near the clock to turn it on or off.")
		return exitOK
	}
	ui.HideConsole()
	if !ui.Confirm("Install ab-win?", "ab-win blocks ads, trackers and malware for all browsers and apps on this PC.\n\nWindows will ask for administrator approval once.\n\nInstall now?") {
		return exitOK
	}
	exe, _ := os.Executable()
	code, err := elevate.Run(exe, []string{"install", "--quiet"})
	switch {
	case err == elevate.ErrCancelled:
		ui.Warn("ab-win", "Administrator approval was declined, so ab-win was not installed.")
		return exitNeedsAdmin
	case err != nil || code != exitOK:
		ui.Error("ab-win", "Install didn't finish. Open a terminal in this folder and run:\n\n    ab-win install\n\nto see what went wrong.")
		return exitError
	}
	startTray()
	ui.Info("ab-win", "Done — protection is on.\n\nLook for the shield icon near the clock. If a site ever breaks: click the shield › Recently blocked › Allow.")
	return exitOK
}

// --- formatting helpers ------------------------------------------------------------

func thousands(n int) string {
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return humanDur(time.Since(t)) + " ago"
}

func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()+0.5))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()+0.5))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
