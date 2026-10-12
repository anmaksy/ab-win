// Package api defines the JSON shapes exchanged over IPC.
package api

import "time"

type Status struct {
	State             string    `json:"state"` // on | off | paused
	PausedUntil       time.Time `json:"paused_until,omitzero"`
	PausedUntilReboot bool      `json:"paused_until_restart,omitempty"`
	BlockedToday      int       `json:"blocked_today"`
	QueriesToday      int       `json:"queries_today"`
	Domains           int       `json:"domains"`
	ListsReady        bool      `json:"lists_ready"`
	ListsUpdated      time.Time `json:"lists_updated,omitzero"`
	Preset            string    `json:"preset"`
	Upstream          string    `json:"upstream"`
	Routing           Routing   `json:"routing"`
	Locked            bool      `json:"locked"`
	Version           string    `json:"version"`
	UpdateAvailable   string    `json:"update_available,omitempty"`
	Problems          []string  `json:"problems,omitempty"`
}

type Routing struct {
	Managed  bool     `json:"managed"` // false in `ab-win run` without --route
	OK       bool     `json:"ok"`
	Adapters []string `json:"adapters,omitempty"` // adapters pointed at us
	Bypassed []string `json:"bypassed,omitempty"` // up adapters with their own DNS (VPN etc.)
}

type DomainParams struct {
	Domain string `json:"domain"`
	Force  bool   `json:"force,omitempty"`
}

type PauseParams struct {
	Duration string `json:"duration"` // Go duration or "reboot"
}

type RecentParams struct {
	N       int    `json:"n"`
	Blocked bool   `json:"blocked"`
	Since   uint64 `json:"since"`
}

type Why struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
	Matched string `json:"matched,omitempty"`
	Active  bool   `json:"active"` // protection currently on
}

type Lists struct {
	Preset     string         `json:"preset"`
	Categories []CategoryInfo `json:"categories"`
	Sources    []SourceInfo   `json:"sources"`
	Domains    int            `json:"domains"`
}

type CategoryInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Warning string `json:"warning,omitempty"`
}

type SourceInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"`
	Count     int       `json:"count"`
	Updated   time.Time `json:"updated,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

type CategoryParams struct {
	Category string `json:"category"`
	Enabled  bool   `json:"enabled"`
}

type UpdateResult struct {
	Changed bool     `json:"changed"`
	Domains int      `json:"domains"`
	Errors  []string `json:"errors,omitempty"`
}

type SelfUpdate struct {
	Current string `json:"current"`
	Latest  string `json:"latest"`
	Newer   bool   `json:"newer"`
	Applied bool   `json:"applied"`
}

// QueryEntry is one line of `recent` (same shape as stats.Query).
type QueryEntry struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Blocked  bool      `json:"blocked"`
	Reason   string    `json:"reason,omitempty"`
	Cached   bool      `json:"cached,omitempty"`
	Upstream string    `json:"upstream,omitempty"`
	Millis   float64   `json:"ms"`
}
