// Package blocklists embeds the built-in seed lists so the binary blocks the
// biggest ad and tracker networks on first run, offline, before any download.
package blocklists

import "embed"

//go:embed *.txt
var FS embed.FS

// Seed lists by category. allowlist-default.txt is always applied.
const (
	Ads       = "ads.txt"
	Trackers  = "trackers.txt"
	Malware   = "malware-cryptojacking.txt"
	Telemetry = "telemetry-windows.txt"
	DoH       = "doh-bypass.txt"
	Allowlist = "allowlist-default.txt"
)
