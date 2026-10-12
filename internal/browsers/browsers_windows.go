//go:build windows

// Package browsers detects browser DNS-over-HTTPS settings that bypass
// ab-win, and (opt-in) sets machine policies that turn browser DoH off
// (PLAN section 6).
package browsers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/windows/registry"
)

type policyValue struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Str   string `json:"str,omitempty"`
	DWord uint32 `json:"dword,omitempty"`
	IsStr bool   `json:"is_str"`
}

// Policies is what harden-browsers sets.
var Policies = []policyValue{
	{Key: `SOFTWARE\Policies\Google\Chrome`, Name: "DnsOverHttpsMode", Str: "off", IsStr: true},
	{Key: `SOFTWARE\Policies\Microsoft\Edge`, Name: "DnsOverHttpsMode", Str: "off", IsStr: true},
	{Key: `SOFTWARE\Policies\BraveSoftware\Brave`, Name: "DnsOverHttpsMode", Str: "off", IsStr: true},
	{Key: `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, Name: "Enabled", DWord: 0},
	{Key: `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, Name: "Locked", DWord: 1},
}

// previous records what was there before we changed it, for --undo.
type previous struct {
	policyValue
	Existed bool `json:"existed"`
}

// Harden writes the policies, saving prior values to backupPath. Needs admin.
func Harden(backupPath string) error {
	var saved []previous
	if b, err := os.ReadFile(backupPath); err == nil {
		json.Unmarshal(b, &saved)
	}
	already := len(saved) > 0
	var errs []error
	for _, p := range Policies {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, p.Key, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Key, err))
			continue
		}
		if !already {
			prev := previous{policyValue: policyValue{Key: p.Key, Name: p.Name, IsStr: p.IsStr}}
			if p.IsStr {
				if v, _, err := k.GetStringValue(p.Name); err == nil {
					prev.Existed, prev.Str = true, v
				}
			} else if v, _, err := k.GetIntegerValue(p.Name); err == nil {
				prev.Existed, prev.DWord = true, uint32(v)
			}
			saved = append(saved, prev)
		}
		if p.IsStr {
			err = k.SetStringValue(p.Name, p.Str)
		} else {
			err = k.SetDWordValue(p.Name, p.DWord)
		}
		if err != nil {
			errs = append(errs, err)
		}
		k.Close()
	}
	b, _ := json.MarshalIndent(saved, "", "  ")
	os.MkdirAll(filepath.Dir(backupPath), 0o755)
	if err := os.WriteFile(backupPath, b, 0o644); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Undo restores the values saved by Harden. Needs admin.
func Undo(backupPath string) error {
	b, err := os.ReadFile(backupPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved []previous
	if err := json.Unmarshal(b, &saved); err != nil {
		return err
	}
	var errs []error
	for _, p := range saved {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p.Key, registry.SET_VALUE)
		if err != nil {
			continue
		}
		switch {
		case !p.Existed:
			k.DeleteValue(p.Name)
		case p.IsStr:
			err = k.SetStringValue(p.Name, p.Str)
		default:
			err = k.SetDWordValue(p.Name, p.DWord)
		}
		if err != nil {
			errs = append(errs, err)
		}
		k.Close()
	}
	if len(errs) == 0 {
		os.Remove(backupPath)
	}
	return errors.Join(errs...)
}

// Hardened reports whether our policies are in place.
func Hardened() bool {
	for _, p := range Policies {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p.Key, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		ok := false
		if p.IsStr {
			v, _, err := k.GetStringValue(p.Name)
			ok = err == nil && v == p.Str
		} else {
			v, _, err := k.GetIntegerValue(p.Name)
			ok = err == nil && uint32(v) == p.DWord
		}
		k.Close()
		if !ok {
			return false
		}
	}
	return true
}

// Finding is a browser setting that bypasses ab-win.
type Finding struct {
	Browser string
	Detail  string
}

var chromium = []struct{ name, dir, policy string }{
	{"Chrome", `Google\Chrome\User Data`, `SOFTWARE\Policies\Google\Chrome`},
	{"Edge", `Microsoft\Edge\User Data`, `SOFTWARE\Policies\Microsoft\Edge`},
	{"Brave", `BraveSoftware\Brave-Browser\User Data`, `SOFTWARE\Policies\BraveSoftware\Brave`},
	{"Vivaldi", `Vivaldi\User Data`, ""},
	{"Opera", ``, ""},
}

func policyOff(key string) bool {
	if key == "" {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("DnsOverHttpsMode")
	return err == nil && v == "off"
}

// Detect checks the current user's browsers for their own DoH setting.
func Detect() []Finding {
	var out []Finding
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	for _, c := range chromium {
		path := filepath.Join(local, c.dir, "Local State")
		if c.name == "Opera" {
			path = filepath.Join(roaming, `Opera Software\Opera Stable\Local State`)
		}
		b, err := os.ReadFile(path)
		if err != nil || policyOff(c.policy) {
			continue
		}
		var st struct {
			DoH struct {
				Mode      string `json:"mode"`
				Templates string `json:"templates"`
			} `json:"dns_over_https"`
		}
		if json.Unmarshal(b, &st) != nil {
			continue
		}
		// "automatic" without a custom template only upgrades when the system
		// resolver is a known DoH provider, which 127.0.0.1 is not.
		if st.DoH.Mode == "secure" || (st.DoH.Templates != "" && st.DoH.Mode != "off") {
			out = append(out, Finding{c.name, "uses its own secure DNS (Settings › Privacy › Use secure DNS), so ab-win can't filter it"})
		}
	}
	profiles, _ := filepath.Glob(filepath.Join(roaming, `Mozilla\Firefox\Profiles\*\prefs.js`))
	re := regexp.MustCompile(`user_pref\("network\.trr\.mode",\s*([0-9])\)`)
	for _, p := range profiles {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := re.FindSubmatch(b); m != nil && (string(m[1]) == "2" || string(m[1]) == "3") {
			out = append(out, Finding{"Firefox", "has DNS over HTTPS switched on by hand (Settings › Privacy › DNS over HTTPS), so ab-win can't filter it"})
			break
		}
	}
	return out
}
