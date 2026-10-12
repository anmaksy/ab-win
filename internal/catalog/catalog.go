// Package catalog maps user-facing categories and presets to the built-in
// seed lists and the upstream lists downloaded at runtime
// (docs/BLOCKLIST-SOURCES.md). Upstream lists are never bundled.
package catalog

import "github.com/anmaksy/ab-win/blocklists"

// Category is what users switch on and off.
type Category struct {
	ID      string
	Name    string
	Default bool
	Warning string // shown when turning it on
	Seed    string // embedded seed file, may be empty
}

var Categories = []Category{
	{ID: "ads", Name: "Ads (includes most trackers)", Default: true, Seed: blocklists.Ads},
	{ID: "trackers", Name: "Trackers & analytics", Default: true, Seed: blocklists.Trackers},
	{ID: "malware", Name: "Malware, phishing, scams", Default: true, Seed: blocklists.Malware},
	{ID: "telemetry", Name: "Windows & Office telemetry", Default: false, Seed: blocklists.Telemetry,
		Warning: "May break Windows Update, Microsoft Store, Defender cloud protection, Office activation or Xbox features."},
	{ID: "doh_bypass", Name: "DoH / VPN bypass", Default: false, Seed: blocklists.DoH,
		Warning: "Also blocks privacy tools and some VPN apps that use their own encrypted DNS."},
}

func CategoryByID(id string) (Category, bool) {
	for _, c := range Categories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// Source is an upstream list.
type Source struct {
	ID       string // file name stem under lists\
	Name     string // shown by `why` and `lists`, in plain words
	Category string
	URL      string
	MinSize  int // entries; a smaller download is treated as broken
}

const hagezi = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"

var all = map[string]Source{
	"hagezi-light":     {ID: "hagezi-light", Name: "HaGeZi Light (ads & trackers)", Category: "ads", URL: hagezi + "light-onlydomains.txt", MinSize: 20000},
	"hagezi-pro":       {ID: "hagezi-pro", Name: "HaGeZi Pro (ads & trackers)", Category: "ads", URL: hagezi + "pro-onlydomains.txt", MinSize: 100000},
	"hagezi-proplus":   {ID: "hagezi-proplus", Name: "HaGeZi Pro++ (ads & trackers)", Category: "ads", URL: hagezi + "pro.plus-onlydomains.txt", MinSize: 100000},
	"oisd-big":         {ID: "oisd-big", Name: "OISD Big (ads & trackers)", Category: "ads", URL: "https://big.oisd.nl/domainswild2", MinSize: 50000},
	"adguard-cname":    {ID: "adguard-cname", Name: "AdGuard CNAME trackers (trackers)", Category: "trackers", URL: "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers_justdomains.txt", MinSize: 1000},
	"frogeye-1p":       {ID: "frogeye-1p", Name: "Frogeye first-party trackers (trackers)", Category: "trackers", URL: "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", MinSize: 1000},
	"hagezi-tif":       {ID: "hagezi-tif", Name: "HaGeZi Threat Intelligence (malware & phishing)", Category: "malware", URL: hagezi + "tif-onlydomains.txt", MinSize: 100000},
	"hagezi-tif-med":   {ID: "hagezi-tif-med", Name: "HaGeZi Threat Intelligence Medium (malware & phishing)", Category: "malware", URL: hagezi + "tif.medium-onlydomains.txt", MinSize: 50000},
	"urlhaus":          {ID: "urlhaus", Name: "abuse.ch URLhaus (malware)", Category: "malware", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", MinSize: 50},
	"hagezi-winoffice": {ID: "hagezi-winoffice", Name: "HaGeZi Windows/Office telemetry", Category: "telemetry", URL: hagezi + "native.winoffice-onlydomains.txt", MinSize: 50},
	"hagezi-doh":       {ID: "hagezi-doh", Name: "HaGeZi DoH bypass", Category: "doh_bypass", URL: hagezi + "doh-onlydomains.txt", MinSize: 500},
}

var presets = map[string][]string{
	"relaxed":    {"hagezi-light", "hagezi-tif-med", "urlhaus", "hagezi-winoffice", "hagezi-doh"},
	"balanced":   {"hagezi-pro", "adguard-cname", "hagezi-tif", "urlhaus", "hagezi-winoffice", "hagezi-doh"},
	"aggressive": {"hagezi-proplus", "oisd-big", "adguard-cname", "frogeye-1p", "hagezi-tif", "urlhaus", "hagezi-winoffice", "hagezi-doh"},
}

// Sources returns the upstream lists for a preset, filtered by enabled categories.
func Sources(preset string, enabled map[string]bool) []Source {
	var out []Source
	for _, id := range presets[preset] {
		s := all[id]
		if enabled[s.Category] {
			out = append(out, s)
		}
	}
	return out
}

// AllSources returns every known upstream list (for the list-health check).
func AllSources() []Source {
	var out []Source
	for _, s := range all {
		out = append(out, s)
	}
	return out
}
