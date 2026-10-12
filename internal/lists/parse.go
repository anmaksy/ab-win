// Package lists parses blocklists in hosts, plain-domain, wildcard and
// ABP/AdGuard DNS syntax (see docs/BLOCKLIST-SOURCES.md, section 3).
package lists

import (
	"bufio"
	"io"
	"strings"

	"github.com/anmaksy/ab-win/internal/domain"
)

// Entry is one usable rule from a list.
type Entry struct {
	Domain string
	Allow  bool // "@@||d^" in ABP syntax
	Exact  bool // "=d" in our own allowlists: match d only, not subdomains
}

// Parse calls fn for every valid entry in r. Invalid lines are skipped.
func Parse(r io.Reader, fn func(Entry)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, string(rune(0xFEFF)))
			first = false
		}
		parseLine(line, fn)
	}
	return sc.Err()
}

// ParseLine returns the entries on a single line (hosts lines can carry several names).
func ParseLine(line string) []Entry {
	var out []Entry
	parseLine(line, func(e Entry) { out = append(out, e) })
	return out
}

var hostsIgnore = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"0.0.0.0": true, "ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true,
	"ip6-mcastprefix": true, "ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
}

func parseLine(line string, fn func(Entry)) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	switch line[0] {
	case '#', '!', '[':
		return
	}
	// Inline comments: "example.com # note". ABP uses '#' for cosmetic rules
	// ("##"), and those are skipped below anyway.
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "\t#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	// ABP / AdGuard DNS syntax.
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@||") {
		allow := strings.HasPrefix(line, "@@")
		rule := strings.TrimPrefix(strings.TrimPrefix(line, "@@"), "||")
		opts := ""
		if i := strings.IndexByte(rule, '$'); i >= 0 {
			rule, opts = rule[:i], rule[i+1:]
		}
		if opts != "" && opts != "important" {
			return
		}
		if !strings.HasSuffix(rule, "^") {
			return
		}
		rule = strings.TrimSuffix(rule, "^")
		if strings.ContainsAny(rule, "/*^|") {
			return
		}
		if d, ok := domain.Normalize(rule); ok {
			fn(Entry{Domain: d, Allow: allow})
		}
		return
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.HasPrefix(line, "/") {
		return
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 && looksLikeIP(fields[0]) {
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			if hostsIgnore[strings.ToLower(f)] {
				continue
			}
			if d, ok := domain.Normalize(f); ok {
				fn(Entry{Domain: d})
			}
		}
		return
	}
	if len(fields) != 1 {
		return
	}
	f := fields[0]
	exact := false
	if strings.HasPrefix(f, "=") {
		exact, f = true, f[1:]
	}
	f = strings.TrimPrefix(f, "*.")
	f = strings.TrimPrefix(f, ".")
	if d, ok := domain.Normalize(f); ok {
		fn(Entry{Domain: d, Exact: exact})
	}
}

func looksLikeIP(s string) bool {
	if strings.Contains(s, ":") {
		return true // IPv6 like ::1 or ::
	}
	dots := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3
}
