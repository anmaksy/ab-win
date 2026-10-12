//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/anmaksy/ab-win/internal/app"
	"github.com/anmaksy/ab-win/internal/paths"
	"github.com/anmaksy/ab-win/internal/version"
)

const (
	runKey       = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ab-win`
)

// PortConflict describes another program holding port 53.
type PortConflict struct {
	PID     int
	Process string
	Service string
	Hint    string
}

func (c *PortConflict) Error() string {
	who := c.Process
	if c.Service != "" {
		who += " (" + c.Service + ")"
	}
	if who == "" {
		who = "another program"
	}
	return fmt.Sprintf("port 53 is already used by %s, PID %d. %s", who, c.PID, c.Hint)
}

var conflictHints = map[string]string{
	"sharedaccess":   "This is Internet Connection Sharing / Mobile hotspot. Turn off Mobile hotspot in Settings, then try again.",
	"com.docker":     "This is Docker Desktop's DNS. Quit Docker Desktop, install ab-win, then start Docker again.",
	"vpnkit":         "This is Docker Desktop's DNS. Quit Docker Desktop, install ab-win, then start Docker again.",
	"adguard":        "Another DNS filter (AdGuard) is running. Use one DNS filter at a time: uninstall or stop it first.",
	"dnscrypt-proxy": "Another DNS filter (dnscrypt-proxy / Simple DNSCrypt) is running. Stop it first.",
	"acrylic":        "Another DNS proxy (Acrylic) is running. Stop it first.",
	"dnsservice":     "Another DNS server (Technitium) is running. Stop it first.",
	"dns.exe":        "The Windows DNS Server role is installed. ab-win can't run next to it.",
}

// CheckPort53 returns nil if 127.0.0.1:53 is free (UDP and TCP).
func CheckPort53() error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err == nil {
		pc.Close()
		l, err2 := net.Listen("tcp", "127.0.0.1:53")
		if err2 == nil {
			l.Close()
			return nil
		}
	}
	return findPortOwner()
}

func findPortOwner() error {
	c := &PortConflict{Hint: "Stop that program, then try again."}
	for _, proto := range []string{"UDP", "TCP"} {
		out, _ := exec.Command("netstat", "-ano", "-p", proto).Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			local := f[1]
			if !(strings.HasSuffix(local, ":53")) {
				continue
			}
			host := strings.TrimSuffix(local, ":53")
			if host != "0.0.0.0" && host != "127.0.0.1" && host != "[::]" && host != "[::1]" {
				continue
			}
			pid, _ := strconv.Atoi(f[len(f)-1])
			c.PID = pid
			break
		}
		if c.PID != 0 {
			break
		}
	}
	if c.PID != 0 {
		out, _ := exec.Command("tasklist", "/svc", "/fi", fmt.Sprintf("PID eq %d", c.PID), "/fo", "csv", "/nh").Output()
		r := strings.Split(strings.TrimSpace(string(out)), "\",\"")
		if len(r) >= 3 {
			c.Process = strings.Trim(r[0], "\"")
			c.Service = strings.Trim(r[2], "\"\r")
			if c.Service == "N/A" {
				c.Service = ""
			}
		}
		key := strings.ToLower(c.Process + " " + c.Service)
		for k, h := range conflictHints {
			if strings.Contains(key, k) {
				c.Hint = h
			}
		}
	}
	return c
}

// Install sets everything up. It must run elevated. out receives progress lines.
func Install(out io.Writer) error {
	p := paths.Default()
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()

	// Upgrading an existing install: stop it first so the port frees up and
	// the binary can be replaced.
	if s, err := m.OpenService(Name); err == nil {
		fmt.Fprintln(out, "Stopping the running ab-win service…")
		if _, err := s.Control(svc.Stop); err == nil {
			waitState(s, svc.Stopped, 30*time.Second)
		}
		s.Close()
	}
	if err := CheckPort53(); err != nil {
		return err
	}

	// Binary.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := paths.InstalledExe()
	if !samePath(self, dst) {
		if err := os.MkdirAll(paths.InstallDir(), 0o755); err != nil {
			return err
		}
		if err := copyFile(self, dst); err != nil {
			return fmt.Errorf("copying to %s: %w", dst, err)
		}
	}
	if err := os.MkdirAll(p.Data, 0o755); err != nil {
		return err
	}
	// An explicit (re)install means "protect me now": skip the failsafe hold-off.
	os.Remove(p.Failsafe())
	// Admins and SYSTEM write, users read (PLAN 3.4).
	exec.Command("icacls", p.Data, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX").Run()

	// Service.
	s, err := m.OpenService(Name)
	cfg := mgr.Config{
		DisplayName:  DisplayName,
		Description:  Description,
		StartType:    mgr.StartAutomatic,
		Dependencies: []string{"Tcpip", "Nsi"},
	}
	if err != nil {
		s, err = m.CreateService(Name, dst, cfg, "service")
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}
	} else {
		cur, _ := s.Config()
		cur.DisplayName, cur.Description, cur.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
		cur.BinaryPathName = syscall.EscapeArg(dst) + " service"
		s.UpdateConfig(cur)
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 600)
	eventlog.InstallAsEventCreate(Name, eventlog.Error|eventlog.Warning|eventlog.Info)

	// Watchdog: SYSTEM task every minute (PLAN 5.4).
	if res, err := exec.Command("schtasks", "/Create", "/F", "/TN", TaskName, "/RU", "SYSTEM",
		"/SC", "MINUTE", "/MO", "1", "/RL", "HIGHEST",
		"/TR", syscall.EscapeArg(dst)+" watchdog").CombinedOutput(); err != nil {
		fmt.Fprintf(out, "Warning: watchdog task not created: %s\n", strings.TrimSpace(string(res)))
	}

	// Tray for every user at logon, and the Installed apps entry.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		k.SetStringValue("ab-win", syscall.EscapeArg(dst)+" tray")
		k.Close()
	}
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE); err == nil {
		k.SetStringValue("DisplayName", "ab-win (ad & malware blocker)")
		k.SetStringValue("DisplayVersion", strings.TrimPrefix(version.Version, "v"))
		k.SetStringValue("Publisher", "ab-win")
		k.SetStringValue("DisplayIcon", dst)
		k.SetStringValue("InstallLocation", paths.InstallDir())
		k.SetStringValue("UninstallString", syscall.EscapeArg(dst)+" uninstall")
		k.SetStringValue("URLInfoAbout", "https://github.com/"+version.Repo)
		k.SetDWordValue("NoModify", 1)
		k.SetDWordValue("NoRepair", 1)
		k.Close()
	}

	fmt.Fprintln(out, "Starting protection…")
	if err := s.Start("service"); err != nil {
		return fmt.Errorf("starting service: %w (see Event Viewer › Windows Logs › Application)", err)
	}
	if err := waitState(s, svc.Running, 30*time.Second); err != nil {
		return err
	}
	return nil
}

// UninstallOptions controls what Uninstall removes.
type UninstallOptions struct {
	KeepData bool
	Out      io.Writer
}

// Uninstall removes everything and restores the original DNS, even if the
// service is already gone. It must run elevated.
func Uninstall(o UninstallOptions) error {
	p := paths.Default()
	var errs []error
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(Name); err == nil {
			fmt.Fprintln(o.Out, "Stopping the service…")
			if _, err := s.Control(svc.Stop); err == nil {
				waitState(s, svc.Stopped, 30*time.Second)
			}
			if err := s.Delete(); err != nil {
				errs = append(errs, fmt.Errorf("deleting service: %w", err))
			}
			s.Close()
		}
		m.Disconnect()
	}
	fmt.Fprintln(o.Out, "Restoring your original DNS settings…")
	if err := app.RouteRestore(p); err != nil {
		errs = append(errs, fmt.Errorf("restoring DNS: %w", err))
	}
	exec.Command("schtasks", "/Delete", "/F", "/TN", TaskName).Run()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		k.DeleteValue("ab-win")
		k.Close()
	}
	registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	eventlog.Remove(Name)

	// Close trays in every session. Only "tray" processes: the un-elevated
	// ab-win.exe that launched us is waiting to show the result.
	exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance Win32_Process -Filter "Name='ab-win.exe'" | Where-Object { $_.CommandLine -match '\stray\s*$' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`).Run()

	if !o.KeepData {
		os.RemoveAll(p.Data)
	}
	// The running exe can't delete itself; a short-lived cmd does it after we exit.
	self, _ := os.Executable()
	if samePath(filepath.Dir(self), paths.InstallDir()) {
		cmd := exec.Command("cmd", "/c", "ping -n 3 127.0.0.1 >nul & rmdir /s /q "+syscall.EscapeArg(paths.InstallDir()))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS}
		cmd.Start()
	} else {
		os.RemoveAll(paths.InstallDir())
	}
	return errors.Join(errs...)
}

func samePath(a, b string) bool {
	ca, _ := filepath.Abs(a)
	cb, _ := filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(ca), filepath.Clean(cb))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Rename a running old binary out of the way (Windows allows that).
	if _, err := os.Stat(dst); err == nil {
		os.Remove(dst + ".old")
		os.Rename(dst, dst+".old")
	}
	tmp := dst + ".new"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
