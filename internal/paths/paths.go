// Package paths names the files ab-win keeps on disk (PLAN section 3.4).
package paths

import (
	"os"
	"path/filepath"
)

// Paths is rooted at a data directory, C:\ProgramData\ab-win in production.
type Paths struct{ Data string }

// Default returns the production layout.
func Default() Paths {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return Paths{Data: filepath.Join(pd, "ab-win")}
}

// InstallDir is where the binary lives once installed.
func InstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "ab-win")
}

func InstalledExe() string { return filepath.Join(InstallDir(), "ab-win.exe") }

func (p Paths) Config() string   { return filepath.Join(p.Data, "config.toml") }
func (p Paths) Allow() string    { return filepath.Join(p.Data, "allow.txt") }
func (p Paths) Block() string    { return filepath.Join(p.Data, "block.txt") }
func (p Paths) ListsDir() string { return filepath.Join(p.Data, "lists") }
func (p Paths) ListsBin() string { return filepath.Join(p.Data, "lists.bin") }
func (p Paths) State() string    { return filepath.Join(p.Data, "state.json") }
func (p Paths) Runtime() string  { return filepath.Join(p.Data, "runtime.json") }
func (p Paths) Failsafe() string { return filepath.Join(p.Data, "failsafe.json") }
func (p Paths) Browsers() string { return filepath.Join(p.Data, "browser-policies.json") }
func (p Paths) LogDir() string   { return filepath.Join(p.Data, "logs") }
func (p Paths) Log() string      { return filepath.Join(p.LogDir(), "ab-win.log") }
