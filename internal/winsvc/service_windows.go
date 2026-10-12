//go:build windows

// Package winsvc installs, runs and removes the ab-win Windows service, its
// watchdog task, the tray autostart and the "Installed apps" entry.
package winsvc

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/anmaksy/ab-win/internal/app"
	"github.com/anmaksy/ab-win/internal/paths"
)

const (
	Name        = "ab-win"
	DisplayName = "ab-win ad & malware blocker"
	Description = "Blocks ads, trackers and malware domains for every app by filtering DNS on this PC."
	TaskName    = "ab-win watchdog"
)

// IsService reports whether we were started by the service control manager.
func IsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// RunService runs the service until Windows stops it.
func RunService() error {
	return svc.Run(Name, &handler{p: paths.Default()})
}

type handler struct{ p paths.Paths }

const pbtAPMResumeAutomatic = 0x12

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	a, err := app.Start(app.Options{Paths: h.p, Route: true})
	if err != nil {
		if el, e := eventlog.Open(Name); e == nil {
			el.Error(1, fmt.Sprintf("ab-win could not start: %v", err))
			el.Close()
		}
		// Never leave DNS pointing at a resolver that isn't running.
		app.RouteRestore(h.p)
		return true, 1
	}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.PowerEvent:
			if c.EventType == pbtAPMResumeAutomatic {
				go func() {
					time.Sleep(5 * time.Second) // let the network come back
					a.Reapply()
				}()
			}
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			// Restore original DNS so the PC works without us; the service
			// takes DNS over again when it starts.
			a.Stop(true)
			return false, 0
		}
	}
	return false, 0
}

// State returns the service state, or ok=false if it isn't installed.
func State() (state svc.State, ok bool) {
	m, err := mgr.Connect()
	if err != nil {
		// Non-admins can't connect with full rights; fall back to a
		// read-only handle.
		h, err2 := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
		if err2 != nil {
			return 0, false
		}
		m = &mgr.Mgr{Handle: h}
	}
	defer m.Disconnect()
	name, _ := windows.UTF16PtrFromString(Name)
	sh, err := windows.OpenService(m.Handle, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, false
	}
	s := &mgr.Service{Name: Name, Handle: sh}
	defer s.Close()
	q, err := s.Query()
	if err != nil {
		return 0, true
	}
	return q.State, true
}

// Installed reports whether the service exists.
func Installed() bool {
	_, ok := State()
	return ok
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		q, err := s.Query()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the service")
}

// Restart stops and starts the service (used after a self-update).
func Restart() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err == nil {
		waitState(s, svc.Stopped, 30*time.Second)
	}
	if err := s.Start("service"); err != nil {
		return err
	}
	return waitState(s, svc.Running, 30*time.Second)
}

var logf = log.Printf
