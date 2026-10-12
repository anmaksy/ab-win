//go:build windows

// Package ui has the few native dialogs ab-win needs and console helpers
// for the double-click and tray cases.
package ui

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mbOK            = 0x0
	mbYesNo         = 0x4
	mbIconInfo      = 0x40
	mbIconWarning   = 0x30
	mbIconError     = 0x10
	mbIconQuestion  = 0x20
	mbSetForeground = 0x10000
	idYes           = 6
)

func box(title, text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	r, _ := windows.MessageBox(0, m, t, flags|mbSetForeground)
	return r
}

func Info(title, text string)  { box(title, text, mbOK|mbIconInfo) }
func Warn(title, text string)  { box(title, text, mbOK|mbIconWarning) }
func Error(title, text string) { box(title, text, mbOK|mbIconError) }

// Confirm shows a Yes/No question.
func Confirm(title, text string) bool {
	return box(title, text, mbYesNo|mbIconQuestion) == idYes
}

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procShowWindow            = windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
)

// OwnConsole reports whether Windows created a console just for us, which
// means we were double-clicked (or started from the Run key) rather than
// launched from a terminal.
func OwnConsole() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 4)
	return n == 1
}

// HideConsole hides and detaches our console window if we own it.
func HideConsole() {
	if !OwnConsole() {
		return
	}
	if h, _, _ := procGetConsoleWindow.Call(); h != 0 {
		procShowWindow.Call(h, 0)
	}
	procFreeConsole.Call()
}

// Open opens a URL or folder with the default handler.
func Open(target string) {
	exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
}
