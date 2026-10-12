//go:build windows

// Package tray is the notification-area icon and menu (PLAN 4.2).
package tray

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/anmaksy/ab-win/internal/api"
	"github.com/anmaksy/ab-win/internal/elevate"
	"github.com/anmaksy/ab-win/internal/ipc"
	"github.com/anmaksy/ab-win/internal/paths"
	"github.com/anmaksy/ab-win/internal/ui"
	"github.com/anmaksy/ab-win/internal/version"
	"github.com/anmaksy/ab-win/internal/winsvc"
)

const recentSlots = 10

// Run shows the tray until the user quits it. One tray per logon session.
func Run() error {
	name, _ := windows.UTF16PtrFromString(`Local\ab-win-tray`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	defer windows.CloseHandle(h)
	ui.HideConsole()
	t := &tray{client: ipc.Client{}}
	systray.Run(t.ready, func() {})
	return nil
}

type tray struct {
	client ipc.Client

	mu     sync.Mutex
	status *api.Status
	icon   int

	header, toggle, pause, pause5, pause60, pauseReboot, resume *systray.MenuItem
	blocked, recent                                             *systray.MenuItem
	recentItems                                                 [recentSlots]*systray.MenuItem
	recentNames                                                 [recentSlots]string
	update, appUpdate, settings, help, install, quit            *systray.MenuItem
}

func (t *tray) ready() {
	systray.SetIcon(Icon(IconOff))
	systray.SetTooltip("ab-win")
	t.header = systray.AddMenuItem("ab-win", "")
	t.header.Disable()
	systray.AddSeparator()
	t.toggle = systray.AddMenuItemCheckbox("Protection on", "Click to turn protection on or off", false)
	t.pause = systray.AddMenuItem("Pause", "Turn protection off for a while; it comes back on by itself")
	t.pause5 = t.pause.AddSubMenuItem("5 minutes", "")
	t.pause60 = t.pause.AddSubMenuItem("1 hour", "")
	t.pauseReboot = t.pause.AddSubMenuItem("Until restart", "")
	t.resume = systray.AddMenuItem("Resume now", "Turn protection back on")
	t.resume.Hide()
	systray.AddSeparator()
	t.blocked = systray.AddMenuItem("Blocked today: –", "")
	t.blocked.Disable()
	t.recent = systray.AddMenuItem("Recently blocked", "A site broken? Click its domain here to allow it")
	for i := range t.recentItems {
		t.recentItems[i] = t.recent.AddSubMenuItem("", "Click to always allow this domain")
		t.recentItems[i].Hide()
	}
	systray.AddSeparator()
	t.update = systray.AddMenuItem("Update lists now", "")
	t.appUpdate = systray.AddMenuItem("Update available", "")
	t.appUpdate.Hide()
	t.install = systray.AddMenuItem("Install protection…", "Install the ab-win service (asks for admin approval once)")
	t.install.Hide()
	t.settings = systray.AddMenuItem("Settings…", "Open the settings folder")
	t.help = systray.AddMenuItem("About / Help", "")
	systray.AddSeparator()
	t.quit = systray.AddMenuItem("Quit tray (protection keeps running)", "")

	go t.loop()
	t.refresh()
	go func() {
		for range time.Tick(3 * time.Second) {
			t.refresh()
		}
	}()
}

func (t *tray) loop() {
	for i := range t.recentItems {
		i := i
		go func() {
			for range t.recentItems[i].ClickedCh {
				t.allow(i)
			}
		}()
	}
	for {
		select {
		case <-t.toggle.ClickedCh:
			t.mu.Lock()
			on := t.status != nil && t.status.State == "on"
			t.mu.Unlock()
			if on {
				t.call("off", nil)
			} else {
				t.call("on", nil)
			}
		case <-t.pause5.ClickedCh:
			t.call("pause", api.PauseParams{Duration: "5m"})
		case <-t.pause60.ClickedCh:
			t.call("pause", api.PauseParams{Duration: "1h"})
		case <-t.pauseReboot.ClickedCh:
			t.call("pause", api.PauseParams{Duration: "reboot"})
		case <-t.resume.ClickedCh:
			t.call("resume", nil)
		case <-t.update.ClickedCh:
			t.update.SetTitle("Updating lists…")
			t.update.Disable()
			go func() {
				var r api.UpdateResult
				err := t.client.Call("update", nil, &r)
				t.update.SetTitle("Update lists now")
				t.update.Enable()
				if err != nil {
					t.showErr(err)
				} else if len(r.Errors) > 0 {
					ui.Warn("ab-win", fmt.Sprintf("Lists updated (%d domains), but some lists could not be downloaded:\n\n%s\n\nThe last good copies are still in use.", r.Domains, strings.Join(r.Errors, "\n")))
				}
				t.refresh()
			}()
		case <-t.appUpdate.ClickedCh:
			go t.selfUpdate()
		case <-t.install.ClickedCh:
			go t.installService()
		case <-t.settings.ClickedCh:
			ui.Open(paths.Default().Data)
		case <-t.help.ClickedCh:
			ui.Open("https://github.com/" + version.Repo + "#readme")
		case <-t.quit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func (t *tray) call(method string, params any) {
	var st api.Status
	if err := t.client.Call(method, params, &st); err != nil {
		t.showErr(err)
		return
	}
	t.apply(&st, nil)
}

func (t *tray) showErr(err error) {
	switch {
	case errors.Is(err, ipc.ErrLocked):
		ui.Info("ab-win", "Managed by administrator.\n\nProtection settings on this PC are locked. Ask the person who set it up.")
	case errors.Is(err, ipc.ErrNotRunning):
		ui.Error("ab-win", "ab-win isn't running.\n\nRestart the PC, or reinstall ab-win from the tray menu.")
	default:
		ui.Error("ab-win", err.Error())
	}
}

func (t *tray) allow(i int) {
	t.mu.Lock()
	d := t.recentNames[i]
	t.mu.Unlock()
	if d == "" {
		return
	}
	if err := t.client.Call("allow", api.DomainParams{Domain: d}, nil); err != nil {
		t.showErr(err)
		return
	}
	ui.Info("ab-win", d+" is now allowed.\n\nReload the page that was broken. To block it again: ab-win unallow "+d)
	t.refresh()
}

func (t *tray) selfUpdate() {
	if !ui.Confirm("ab-win", "Download and install the new version of ab-win now?\n\nProtection restarts for a few seconds.") {
		return
	}
	var r api.SelfUpdate
	if err := t.client.Call("self_update", map[string]bool{"apply": true}, &r); err != nil {
		t.showErr(err)
		return
	}
	if r.Applied {
		ui.Info("ab-win", "Updated to "+r.Latest+". Restart the tray from the Start menu or sign out and back in to get its new version.")
	}
}

func (t *tray) installService() {
	exe, _ := os.Executable()
	code, err := elevate.Run(exe, []string{"install", "--quiet"})
	switch {
	case errors.Is(err, elevate.ErrCancelled):
		return
	case err != nil:
		ui.Error("ab-win", "Install failed: "+err.Error())
	case code != 0:
		ui.Error("ab-win", "Install failed. Open a terminal and run `ab-win install` to see why.")
	default:
		// Hand over to the installed copy's tray.
		if !strings.EqualFold(exe, paths.InstalledExe()) {
			exec.Command(paths.InstalledExe(), "tray").Start()
			systray.Quit()
		}
	}
	t.refresh()
}

// refresh polls the service and updates the menu.
func (t *tray) refresh() {
	var st api.Status
	err := t.client.Call("status", nil, &st)
	if err != nil {
		t.apply(nil, nil)
		return
	}
	var recent []string
	t.client.Call("recent_blocked", nil, &recent)
	t.apply(&st, recent)
}

func (t *tray) apply(st *api.Status, recent []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status = st
	if st == nil {
		installed := winsvc.Installed()
		t.setIcon(IconProblem)
		if !installed {
			t.setIcon(IconOff)
			t.header.SetTitle("ab-win — Not installed")
			systray.SetTooltip("ab-win — not installed")
			t.install.Show()
		} else {
			t.header.SetTitle("ab-win — Not running")
			tip := "ab-win — problem: the service isn't running"
			if f, ok := winsvc.ReadFailsafe(); ok {
				tip += "\nInternet uses normal DNS (" + f.Reason + ")"
			}
			systray.SetTooltip(tip)
			t.install.SetTitle("Repair protection…")
			t.install.Show()
		}
		for _, m := range []*systray.MenuItem{t.toggle, t.pause, t.update, t.recent} {
			m.Disable()
		}
		return
	}
	t.install.Hide()
	for _, m := range []*systray.MenuItem{t.toggle, t.pause, t.update, t.recent} {
		m.Enable()
	}
	var head, tip string
	switch st.State {
	case "on":
		t.setIcon(IconOn)
		head, tip = "ab-win — Protected", "ab-win — protected"
		t.toggle.Check()
		t.toggle.SetTitle("Protection on")
		t.resume.Hide()
		t.pause.Show()
	case "paused":
		t.setIcon(IconPaused)
		until := "until restart"
		if !st.PausedUntil.IsZero() {
			until = "until " + st.PausedUntil.Local().Format("15:04")
		}
		head, tip = "ab-win — Paused "+until, "ab-win — paused "+until
		t.toggle.Uncheck()
		t.toggle.SetTitle("Protection paused")
		t.resume.Show()
		t.pause.Hide()
	default:
		t.setIcon(IconOff)
		head, tip = "ab-win — Off", "ab-win — protection off"
		t.toggle.Uncheck()
		t.toggle.SetTitle("Protection off — click to turn on")
		t.resume.Hide()
		t.pause.Show()
	}
	if len(st.Problems) > 0 && st.State == "on" {
		t.setIcon(IconProblem)
		tip += "\n" + st.Problems[0]
	}
	if st.Locked {
		head += " (managed by administrator)"
		t.toggle.Disable()
		t.pause.Disable()
	}
	t.header.SetTitle(head)
	if len(tip) > 127 { // Windows tooltip limit
		tip = tip[:124] + "…"
	}
	systray.SetTooltip(tip)
	t.blocked.SetTitle(fmt.Sprintf("Blocked today: %s", thousands(st.BlockedToday)))
	if st.UpdateAvailable != "" {
		t.appUpdate.SetTitle("Update available: " + st.UpdateAvailable)
		t.appUpdate.Show()
	} else {
		t.appUpdate.Hide()
	}
	if recent != nil {
		for i := range t.recentItems {
			if i < len(recent) {
				t.recentNames[i] = recent[i]
				t.recentItems[i].SetTitle("Allow " + recent[i])
				t.recentItems[i].Show()
			} else {
				t.recentNames[i] = ""
				t.recentItems[i].Hide()
			}
		}
		if len(recent) == 0 {
			t.recent.SetTitle("Recently blocked (none yet)")
		} else {
			t.recent.SetTitle("Recently blocked")
		}
	}
}

func (t *tray) setIcon(i int) {
	if t.icon != i || t.status == nil {
		systray.SetIcon(Icon(i))
		t.icon = i
	}
}

func thousands(n int) string {
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}
