// Package updater downloads upstream lists with sanity checks and compiles
// them, together with the built-in seeds, into lists.bin.
package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anmaksy/ab-win/blocklists"
	"github.com/anmaksy/ab-win/internal/catalog"
	"github.com/anmaksy/ab-win/internal/lists"
	"github.com/anmaksy/ab-win/internal/policy"
)

// MaxListBytes caps a single download (PLAN section 9).
const MaxListBytes = 50 << 20

// Meta is what we remember about each downloaded list.
type Meta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Count        int       `json:"count"`
	SHA256       string    `json:"sha256"`
	Updated      time.Time `json:"updated"`
	Checked      time.Time `json:"checked"`
	LastError    string    `json:"last_error,omitempty"`
}

// Updater fetches lists into Dir.
type Updater struct {
	Dir       string
	Client    *http.Client
	Sentinels []string // exact-match allowlist sentinels; a list containing one is rejected
	Logf      func(format string, args ...any)
}

func (u *Updater) logf(format string, args ...any) {
	if u.Logf != nil {
		u.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (u *Updater) metaPath() string { return filepath.Join(u.Dir, "meta.json") }

// LoadMeta returns stored metadata for all lists.
func (u *Updater) LoadMeta() map[string]Meta {
	m := map[string]Meta{}
	if b, err := os.ReadFile(u.metaPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func (u *Updater) saveMeta(m map[string]Meta) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := u.metaPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, u.metaPath())
}

// Errors returned for rejected updates.
var (
	ErrTooSmall = errors.New("list is suspiciously small")
	ErrShrunk   = errors.New("list shrank by more than 50%")
	ErrGrew     = errors.New("list grew by more than 300%")
	ErrPoisoned = errors.New("list contains a protected domain")
	ErrTooLarge = errors.New("list is larger than 50 MB")
	ErrNotHTTPS = errors.New("list URL must use HTTPS")
)

// UpdateAll fetches every source. It returns true if any list changed.
func (u *Updater) UpdateAll(ctx context.Context, srcs []catalog.Source) (changed bool, errs []error) {
	if err := os.MkdirAll(u.Dir, 0o755); err != nil {
		return false, []error{err}
	}
	meta := u.LoadMeta()
	for _, s := range srcs {
		m := meta[s.ID]
		c, nm, err := u.fetch(ctx, s, m)
		nm.Checked = time.Now()
		if err != nil {
			nm.LastError = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
			u.logf("update %s: %v (keeping last good copy)", s.ID, err)
		} else {
			nm.LastError = ""
		}
		meta[s.ID] = nm
		changed = changed || c
	}
	if err := u.saveMeta(meta); err != nil {
		errs = append(errs, err)
	}
	return changed, errs
}

func (u *Updater) fetch(ctx context.Context, s catalog.Source, m Meta) (bool, Meta, error) {
	if len(s.URL) < 8 || s.URL[:8] != "https://" {
		return false, m, ErrNotHTTPS
	}
	rawPath := filepath.Join(u.Dir, s.ID+".txt")
	_, statErr := os.Stat(rawPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return false, m, err
	}
	req.Header.Set("User-Agent", "ab-win (+https://github.com/anmaksy/ab-win)")
	if statErr == nil {
		if m.ETag != "" {
			req.Header.Set("If-None-Match", m.ETag)
		}
		if m.LastModified != "" {
			req.Header.Set("If-Modified-Since", m.LastModified)
		}
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return false, m, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, m, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
	if err != nil {
		return false, m, err
	}
	if len(body) > MaxListBytes {
		return false, m, ErrTooLarge
	}
	count, err := u.Check(body, s.MinSize, m.Count)
	if err != nil {
		return false, m, err
	}
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	if hexSum == m.SHA256 && statErr == nil {
		m.ETag, m.LastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
		return false, m, nil
	}
	tmp := rawPath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return false, m, err
	}
	if err := os.Rename(tmp, rawPath); err != nil {
		return false, m, err
	}
	u.logf("updated %s: %d domains, sha256 %s", s.ID, count, hexSum)
	return true, Meta{
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
		Count: count, SHA256: hexSum, Updated: time.Now(),
	}, nil
}

// Check parses a downloaded list and applies the sanity rules. prevCount is
// the size of the last accepted copy (0 if none).
func (u *Updater) Check(body []byte, minSize, prevCount int) (int, error) {
	sentinel := make(map[string]bool, len(u.Sentinels))
	for _, s := range u.Sentinels {
		sentinel[s] = true
	}
	count := 0
	var poisoned string
	lists.Parse(bytes.NewReader(body), func(e lists.Entry) {
		if e.Allow {
			return
		}
		count++
		if sentinel[e.Domain] && poisoned == "" {
			poisoned = e.Domain
		}
	})
	if poisoned != "" {
		return count, fmt.Errorf("%w (%s)", ErrPoisoned, poisoned)
	}
	if count < minSize {
		return count, fmt.Errorf("%w (%d entries)", ErrTooSmall, count)
	}
	if prevCount > 0 {
		if count < prevCount/2 {
			return count, fmt.Errorf("%w (%d → %d)", ErrShrunk, prevCount, count)
		}
		if count > prevCount*4 {
			return count, fmt.Errorf("%w (%d → %d)", ErrGrew, prevCount, count)
		}
	}
	return count, nil
}

// Compile builds a snapshot from the seeds of enabled categories plus every
// downloaded upstream list for the preset.
func Compile(listsDir, preset string, enabled map[string]bool) (*policy.Snapshot, error) {
	type input struct {
		name string
		open func() (io.ReadCloser, error)
	}
	var inputs []input
	for _, c := range catalog.Categories {
		if !enabled[c.ID] || c.Seed == "" {
			continue
		}
		seed := c.Seed
		inputs = append(inputs, input{"built-in " + strings.ReplaceAll(c.ID, "_", " ") + " list",
			func() (io.ReadCloser, error) { return blocklists.FS.Open(seed) }})
	}
	for _, s := range catalog.Sources(preset, enabled) {
		path := filepath.Join(listsDir, s.ID+".txt")
		if _, err := os.Stat(path); err != nil {
			continue // not downloaded yet
		}
		inputs = append(inputs, input{s.Name, func() (io.ReadCloser, error) { return os.Open(path) }})
	}
	b := policy.NewBuilder()
	// Two streaming passes keep peak memory to the hash map: add everything,
	// then drop entries whose parent domain is also listed.
	for pass := 0; pass < 2; pass++ {
		for _, in := range inputs {
			f, err := in.open()
			if err != nil {
				continue
			}
			var id uint16
			if pass == 0 {
				id = b.AddList(in.name)
			}
			lists.Parse(f, func(e lists.Entry) {
				if e.Allow {
					return
				}
				if pass == 0 {
					b.Add(id, e.Domain)
				} else {
					b.Prune(e.Domain)
				}
			})
			f.Close()
		}
	}
	return b.Build(), nil
}

// BuiltinAllow loads the embedded default allowlist and returns it and its
// exact-match sentinels.
func BuiltinAllow() (policy.RuleSet, []string) {
	r := policy.NewRuleSet()
	var sentinels []string
	f, err := blocklists.FS.Open(blocklists.Allowlist)
	if err != nil {
		return r, nil
	}
	defer f.Close()
	lists.Parse(f, func(e lists.Entry) {
		if e.Exact {
			r.Exact[e.Domain] = true
			sentinels = append(sentinels, e.Domain)
		} else {
			r.Suffix[e.Domain] = true
		}
	})
	return r, sentinels
}

// HealthResult is one line of the list-health report.
type HealthResult struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// Health downloads every known upstream list and checks it parses and is
// within expected size (the weekly CI job).
func Health(ctx context.Context, client *http.Client, srcs []catalog.Source) []HealthResult {
	_, sentinels := BuiltinAllow()
	u := &Updater{Client: client, Sentinels: sentinels}
	var out []HealthResult
	for _, s := range srcs {
		r := HealthResult{ID: s.ID, URL: s.URL}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		resp, err := client.Do(req)
		if err == nil {
			var body []byte
			body, err = io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
			resp.Body.Close()
			if err == nil && resp.StatusCode != 200 {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			if err == nil {
				r.Count, err = u.Check(body, s.MinSize, 0)
			}
		}
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}
