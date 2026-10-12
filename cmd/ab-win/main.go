//go:build windows

// Command ab-win is the service, CLI and tray in one executable.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/term"

	"github.com/anmaksy/ab-win/internal/elevate"
	"github.com/anmaksy/ab-win/internal/ipc"
	"github.com/anmaksy/ab-win/internal/ui"
	"github.com/anmaksy/ab-win/internal/winsvc"
)

// Exit codes (PLAN 4.1).
const (
	exitOK           = 0
	exitError        = 1
	exitNotInstalled = 2
	exitNeedsAdmin   = 3
)

// out is where command output goes; an elevated child writes to a file
// that the parent prints.
var (
	out     io.Writer = os.Stdout
	errOut  io.Writer = os.Stderr
	jsonOut bool
	fancy   bool // TTY and colour allowed: symbols and ANSI colour
)

func main() {
	if winsvc.IsService() {
		if err := winsvc.RunService(); err != nil {
			os.Exit(exitError)
		}
		return
	}
	os.Exit(run(os.Args[1:]))
}

type cli struct {
	args  []string
	flags map[string]string
}

func (c *cli) has(names ...string) bool {
	for _, n := range names {
		if _, ok := c.flags[n]; ok {
			return true
		}
	}
	return false
}

func (c *cli) flag(name, def string) string {
	if v, ok := c.flags[name]; ok && v != "" {
		return v
	}
	return def
}

func (c *cli) arg(i int) string {
	if i < len(c.args) {
		return c.args[i]
	}
	return ""
}

// valueFlags take the next argument as their value.
var valueFlags = map[string]bool{"--listen": true, "--data": true, "-n": true, "--elevated-output": true}

func parse(args []string) *cli {
	c := &cli{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			name, val, hasVal := strings.Cut(a, "=")
			if !hasVal && valueFlags[name] && i+1 < len(args) {
				val = args[i+1]
				i++
			}
			c.flags[name] = val
			continue
		}
		c.args = append(c.args, a)
	}
	return c
}

func run(args []string) int {
	c := parse(args)
	if p := c.flag("--elevated-output", ""); p != "" {
		if f, err := os.Create(p); err == nil {
			defer f.Close()
			out, errOut = f, f
		}
	} else {
		fancy = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
		if fancy {
			enableVT()
		}
	}
	jsonOut = c.has("--json")

	if len(c.args) == 0 {
		if c.has("-h", "--help", "-?") {
			return cmdHelp(c)
		}
		if c.has("-v", "--version") {
			return cmdVersion(c)
		}
		if ui.OwnConsole() {
			return doubleClick()
		}
		return cmdHelp(c)
	}
	cmd := strings.ToLower(c.args[0])
	c.args = c.args[1:]
	if c.has("-h", "--help") {
		return cmdHelp(&cli{args: []string{cmd}})
	}
	if f, ok := commands[cmd]; ok {
		return f.run(c)
	}
	fmt.Fprintf(errOut, "Unknown command %q. Run `ab-win help` to see what's available.\n", cmd)
	return exitError
}

func enableVT() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}

// Symbols and colour, only for a TTY with colour allowed.
func sym(kind string) string {
	if !fancy {
		switch kind {
		case "ok":
			return "OK:"
		case "warn":
			return "Warning:"
		case "fail":
			return "Problem:"
		case "blocked":
			return "BLOCKED"
		}
		return "-"
	}
	switch kind {
	case "ok":
		return "\x1b[32m✔\x1b[0m"
	case "warn":
		return "\x1b[33m!\x1b[0m"
	case "fail":
		return "\x1b[31m✖\x1b[0m"
	}
	return "·"
}

func bold(s string) string {
	if !fancy {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func dim(s string) string {
	if !fancy {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

// serviceErr turns IPC errors into a message and exit code.
func serviceErr(err error) int {
	switch {
	case errors.Is(err, ipc.ErrNotRunning):
		if !winsvc.Installed() {
			fmt.Fprintln(errOut, "ab-win is not installed. Run `ab-win install` (or double-click ab-win.exe).")
			return exitNotInstalled
		}
		fmt.Fprintln(errOut, "The ab-win service isn't running. Run `ab-win doctor` to find out why, or `ab-win install` to repair it.")
		return exitError
	case errors.Is(err, ipc.ErrLocked):
		fmt.Fprintln(errOut, "Settings are managed by an administrator (lock_settings is on). Run this from an administrator terminal.")
		return exitNeedsAdmin
	}
	fmt.Fprintln(errOut, "Error:", err)
	return exitError
}

// elevated re-runs this command through UAC and relays its output.
func elevated(args []string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitError
	}
	tmp, err := os.CreateTemp("", "ab-win-*.txt")
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitError
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	fmt.Fprintln(out, dim("Asking Windows for administrator approval…"))
	code, err := elevate.Run(exe, append(args, "--elevated-output", tmp.Name()))
	if b, rerr := os.ReadFile(tmp.Name()); rerr == nil {
		if fancy {
			out.Write(b)
		} else {
			out.Write([]byte(stripANSI(string(b))))
		}
	}
	if errors.Is(err, elevate.ErrCancelled) {
		fmt.Fprintln(errOut, "Administrator approval was declined, so nothing was changed.")
		return exitNeedsAdmin
	}
	if err != nil {
		fmt.Fprintln(errOut, "Could not get administrator rights:", err)
		return exitNeedsAdmin
	}
	return code
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
