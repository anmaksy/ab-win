//go:build windows

// Package doctor diagnoses why blocking might not work and says what to do.
package doctor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows/svc"

	"github.com/anmaksy/ab-win/internal/api"
	"github.com/anmaksy/ab-win/internal/browsers"
	"github.com/anmaksy/ab-win/internal/dnsserver"
	"github.com/anmaksy/ab-win/internal/ipc"
	"github.com/anmaksy/ab-win/internal/netcfg"
	"github.com/anmaksy/ab-win/internal/upstream"
	"github.com/anmaksy/ab-win/internal/winsvc"
)

// Level of a check result.
type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Fail Level = "fail"
	Info Level = "info"
)

// Check is one line of the report.
type Check struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Run performs all checks.
func Run() []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }

	state, installed := winsvc.State()
	running := installed && state == svc.Running
	switch {
	case !installed:
		add(Check{"Service", Fail, "ab-win is not installed", "Run `ab-win install` (or double-click ab-win.exe)."})
	case !running:
		add(Check{"Service", Fail, "the ab-win service is installed but not running", "Run `ab-win install` again to repair it."})
	default:
		add(Check{"Service", OK, "running", ""})
	}
	if f, ok := winsvc.ReadFailsafe(); ok {
		add(Check{"Failsafe", Warn, fmt.Sprintf("at %s the watchdog gave DNS back to Windows: %s", f.Time.Format("Jan 2 15:04"), f.Reason),
			"ab-win takes DNS back by itself once it has run stably for 2 minutes. If this repeats, look at C:\\ProgramData\\ab-win\\logs\\ab-win.log."})
	}
	if !running {
		if err := winsvc.CheckPort53(); err != nil {
			add(Check{"Port 53", Fail, err.Error(), ""})
		} else {
			add(Check{"Port 53", OK, "free", ""})
		}
	}

	var st api.Status
	if running {
		if err := (ipc.Client{}).Call("status", nil, &st); err != nil {
			add(Check{"Control", Fail, "the service doesn't answer: " + err.Error(), "Restart the PC; if it persists, run `ab-win install` again."})
		} else {
			lvl, detail := OK, "protection "+st.State
			if st.State != "on" {
				lvl = Warn
			}
			add(Check{"Protection", lvl, detail, map[bool]string{true: "", false: "Run `ab-win on`."}[st.State == "on"]})
			if !st.ListsReady || st.Domains == 0 {
				add(Check{"Lists", Fail, "no blocklist loaded", "Run `ab-win update`."})
			} else {
				age := time.Since(st.ListsUpdated)
				lvl := OK
				fix := ""
				if age > 72*time.Hour {
					lvl, fix = Warn, "Run `ab-win update`; check that raw.githubusercontent.com is reachable."
				}
				add(Check{"Lists", lvl, fmt.Sprintf("%d domains, compiled %s ago", st.Domains, age.Round(time.Minute)), fix})
			}
		}
	}

	// Adapters.
	ads, err := netcfg.Adapters()
	if err != nil {
		add(Check{"Network", Warn, "can't list network adapters: " + err.Error(), ""})
	}
	for _, a := range ads {
		if !a.Up || !a.HasGateway {
			continue
		}
		switch {
		case !running:
			add(Check{"Adapter " + a.Name, Info, fmt.Sprintf("DNS → %s", strings.Join(a.DNS, ", ")), ""})
		case a.PointsAtUs():
			add(Check{"Adapter " + a.Name, OK, "DNS → ab-win", ""})
		case a.VPN:
			add(Check{"Adapter " + a.Name, Warn, fmt.Sprintf("VPN is handling DNS (%s) — blocking inactive on that connection", strings.Join(a.DNS, ", ")),
				"This is normal for work VPNs. For a personal VPN, set force_vpn = true in C:\\ProgramData\\ab-win\\config.toml and run `ab-win reload` (can break company-internal names)."})
		default:
			add(Check{"Adapter " + a.Name, Fail, fmt.Sprintf("DNS → %s (not ab-win)", strings.Join(a.DNS, ", ")),
				"Restart the ab-win service, or run `ab-win install` again. If something keeps changing it back, another app is managing DNS."})
		}
	}

	// End to end through Windows' own resolver.
	if running {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := net.DefaultResolver.LookupHost(ctx, dnsserver.TestDomain)
		cancel()
		if err == nil && len(ips) > 0 && (ips[0] == "0.0.0.0" || ips[0] == "::") {
			add(Check{"End-to-end", OK, "Windows lookups go through ab-win", ""})
		} else {
			add(Check{"End-to-end", Fail, "Windows lookups do not reach ab-win", "See the adapter lines above. Run `ipconfig /flushdns` and try again."})
		}
	}

	// Upstream reachability, checked directly (not through the service).
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	for _, r := range []upstream.Resolver{upstream.CloudflareSecurity(), upstream.Quad9()} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := r.Exchange(ctx, m)
		cancel()
		if err != nil {
			add(Check{"Upstream " + r.Name(), Warn, "unreachable: " + err.Error(),
				"If this network blocks encrypted DNS, ab-win falls back to the network's own DNS automatically. You can also set upstream = \"system\"."})
		} else {
			add(Check{"Upstream " + r.Name(), OK, fmt.Sprintf("reachable (%d ms)", time.Since(start).Milliseconds()), ""})
		}
	}

	// Browsers.
	for _, f := range browsers.Detect() {
		add(Check{"Browser " + f.Browser, Warn, f.Detail,
			"Turn that setting off in the browser, or run `ab-win harden-browsers` to switch it off with a policy for all users."})
	}
	if browsers.Hardened() {
		add(Check{"Browsers", Info, "DoH-off policies are applied (browsers show \"Managed by your organization\")", "Undo with `ab-win harden-browsers --undo`."})
	}
	return out
}
