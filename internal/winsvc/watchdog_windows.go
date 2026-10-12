//go:build windows

package winsvc

import (
	"encoding/json"
	"os"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/anmaksy/ab-win/internal/app"
	"github.com/anmaksy/ab-win/internal/dnsserver"
	"github.com/anmaksy/ab-win/internal/netcfg"
	"github.com/anmaksy/ab-win/internal/paths"
)

// Failsafe is written when the watchdog had to give DNS back to Windows.
type Failsafe struct {
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
}

// ReadFailsafe returns the failsafe record, if any. Readable by any user.
func ReadFailsafe() (Failsafe, bool) {
	var f Failsafe
	b, err := os.ReadFile(paths.Default().Failsafe())
	if err != nil {
		return f, false
	}
	return f, json.Unmarshal(b, &f) == nil
}

type watchState struct {
	Failures int       `json:"failures"`
	Last     time.Time `json:"last"`
}

// Probe asks the loopback resolver for the test domain.
func Probe() bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dnsserver.TestDomain), dns.TypeA)
	c := &dns.Client{Timeout: 2 * time.Second}
	for i := 0; i < 3; i++ {
		if r, _, err := c.Exchange(m, "127.0.0.1:53"); err == nil && len(r.Answer) == 1 {
			return true
		}
	}
	return false
}

// Watchdog runs once a minute as SYSTEM (scheduled task). If the service is
// dead or not answering two checks in a row, it restores the original DNS so
// the PC keeps working, and leaves a failsafe note for the tray.
func Watchdog() error {
	p := paths.Default()
	statePath := p.Data + `\watchdog.json`
	var ws watchState
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &ws)
	}
	save := func() {
		b, _ := json.Marshal(ws)
		os.WriteFile(statePath, b, 0o644)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		// Service gone: make sure DNS isn't left pointing at nothing.
		restore(p, "service is not installed")
		return nil
	}
	defer s.Close()

	q, _ := s.Query()
	if q.State == svc.Running && Probe() {
		if ws.Failures != 0 {
			ws = watchState{}
			save()
		}
		return nil
	}
	ws.Failures++
	ws.Last = time.Now()
	save()

	if q.State == svc.Stopped {
		if c, err := s.Config(); err == nil && c.StartType != mgr.StartDisabled {
			if s.Start("service") == nil {
				waitState(s, svc.Running, 20*time.Second)
				if Probe() {
					return nil
				}
			}
		}
	}
	if ws.Failures >= 2 || q.State == svc.Stopped {
		restore(p, "ab-win stopped answering DNS")
	}
	return nil
}

func restore(p paths.Paths, reason string) {
	mgr := &netcfg.Manager{Path: p.State()}
	if !mgr.HasState() && !anyLoopback() {
		return
	}
	app.RouteRestore(p)
	b, _ := json.Marshal(Failsafe{Time: time.Now(), Reason: reason})
	os.WriteFile(p.Failsafe(), b, 0o644)
}

func anyLoopback() bool {
	ads, _ := netcfg.Adapters()
	for _, a := range ads {
		if v4, _ := netcfg.StaticDNS(a.GUID); v4 == netcfg.LoopbackV4 {
			return true
		}
	}
	return false
}
