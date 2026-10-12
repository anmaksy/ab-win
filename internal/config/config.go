// Package config loads and saves C:\ProgramData\ab-win\config.toml and the
// small runtime state file next to it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the user-editable settings file.
type Config struct {
	Preset             string          `toml:"preset"`   // relaxed | balanced | aggressive
	Upstream           string          `toml:"upstream"` // cloudflare-security | cloudflare | quad9 | system
	Categories         map[string]bool `toml:"categories"`
	LockSettings       bool            `toml:"lock_settings"`  // only admins may change anything
	QueryLog           bool            `toml:"query_log"`      // keep recent queries in memory
	QueryLogSize       int             `toml:"query_log_size"` // ring buffer length
	CNAMECheck         bool            `toml:"cname_check"`    // block names that CNAME to a blocked domain
	ForceVPN           bool            `toml:"force_vpn"`      // also point VPN adapters at loopback (breaks split DNS)
	UpdateHours        int             `toml:"update_hours"`   // list refresh interval
	CheckForAppUpdates bool            `toml:"check_for_app_updates"`
}

// Default returns the settings a user gets without opening anything: Balanced.
func Default() Config {
	return Config{
		Preset:   "balanced",
		Upstream: "cloudflare-security",
		Categories: map[string]bool{
			"ads": true, "trackers": true, "malware": true,
			"telemetry": false, "doh_bypass": false,
		},
		QueryLog:           true,
		QueryLogSize:       10000,
		CNAMECheck:         true,
		UpdateHours:        24,
		CheckForAppUpdates: true,
	}
}

// Validate rejects values we can't act on.
func (c *Config) Validate() error {
	switch c.Preset {
	case "relaxed", "balanced", "aggressive":
	default:
		return fmt.Errorf("preset %q: use relaxed, balanced or aggressive", c.Preset)
	}
	switch c.Upstream {
	case "cloudflare-security", "cloudflare", "quad9", "system":
	default:
		return fmt.Errorf("upstream %q: use cloudflare-security, cloudflare, quad9 or system", c.Upstream)
	}
	if c.QueryLogSize < 100 || c.QueryLogSize > 1_000_000 {
		c.QueryLogSize = 10000
	}
	if c.UpdateHours < 1 {
		c.UpdateHours = 24
	}
	return nil
}

// Load reads path, filling in defaults for anything missing. A missing file is not an error.
func Load(path string) (Config, error) {
	c := Default()
	_, err := toml.DecodeFile(path, &c)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Default(), fmt.Errorf("%s: %w", path, err)
	}
	d := Default()
	for k, v := range d.Categories {
		if _, ok := c.Categories[k]; !ok {
			c.Categories[k] = v
		}
	}
	return c, c.Validate()
}

const header = `# ab-win settings. Most people never need to edit this file.
# Changes made with the ab-win CLI or tray are written here too.
# preset:   relaxed | balanced | aggressive
# upstream: cloudflare-security | cloudflare | quad9 | system
# lock_settings = true lets only administrators turn protection off or change rules.

`

// Save writes c atomically.
func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	f.WriteString(header)
	err = toml.NewEncoder(f).Encode(c)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Runtime is state the service owns: on/off and pause.
type Runtime struct {
	Enabled     bool      `json:"enabled"`
	PausedUntil time.Time `json:"paused_until,omitzero"`
}

func LoadRuntime(path string) Runtime {
	r := Runtime{Enabled: true}
	b, err := os.ReadFile(path)
	if err == nil {
		json.Unmarshal(b, &r)
	}
	return r
}

func SaveRuntime(path string, r Runtime) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
