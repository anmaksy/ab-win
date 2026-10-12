// Package domain normalises and validates DNS names coming from blocklists,
// user input and DNS queries.
package domain

import (
	"strings"

	"golang.org/x/net/idna"
)

// MaxLen is the longest textual domain name we accept (RFC 1035, without the root dot).
const MaxLen = 253

// Normalize lower-cases s, strips a trailing dot, converts IDN to punycode and
// validates label rules. It returns false for anything that isn't a usable
// domain with at least one dot.
func Normalize(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	if !isASCII(s) {
		a, err := idna.Lookup.ToASCII(s)
		if err != nil {
			return "", false
		}
		s = a
	}
	s = strings.ToLower(s)
	if !Valid(s) || !strings.Contains(s, ".") {
		return "", false
	}
	return s, true
}

// NormalizeQuery is like Normalize but accepts single-label names, which
// show up in real DNS queries (for example "wpad" or "router").
func NormalizeQuery(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	return s
}

// Valid reports whether s (already lower-case ASCII) follows label rules:
// 1–63 characters per label, letters, digits, hyphen and underscore, and no
// label that starts or ends with a hyphen. Underscore is allowed because real
// DNS names use it (_dmarc, SRV records) and some lists contain it.
func Valid(s string) bool {
	if len(s) == 0 || len(s) > MaxLen {
		return false
	}
	labelLen := 0
	var prev byte = '.'
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 || prev == '-' {
				return false
			}
			labelLen = 0
		case c == '-':
			if labelLen == 0 {
				return false
			}
			labelLen++
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
			labelLen++
		default:
			return false
		}
		if labelLen > 63 {
			return false
		}
		prev = c
	}
	return labelLen > 0 && prev != '-'
}

// Parent returns the name with its first label removed, or "" if there is no parent.
func Parent(s string) string {
	i := strings.IndexByte(s, '.')
	if i < 0 {
		return ""
	}
	return s[i+1:]
}

// IsTLD reports whether s has no dot, which means a user rule would match an
// entire top-level domain.
func IsTLD(s string) bool { return !strings.Contains(s, ".") }

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
