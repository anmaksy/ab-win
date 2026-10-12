// Package stats keeps counters and an in-memory ring buffer of recent
// queries. Nothing here is written to disk.
package stats

import (
	"sync"
	"time"
)

// Query is one entry in the query log.
type Query struct {
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

// Stats is safe for concurrent use.
type Stats struct {
	mu           sync.Mutex
	enabled      bool
	ring         []Query
	next         int
	full         bool
	seq          uint64
	day          string
	blockedToday int
	queriesToday int
	total        uint64
	totalBlocked uint64
	now          func() time.Time
}

func New(size int, logQueries bool) *Stats {
	return &Stats{ring: make([]Query, size), enabled: logQueries, now: time.Now}
}

// Configure changes the log size and on/off state. Resizing clears the log.
func (s *Stats) Configure(size int, logQueries bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size != len(s.ring) || !logQueries {
		s.ring = make([]Query, size)
		s.next, s.full = 0, false
	}
	s.enabled = logQueries
}

func (s *Stats) rollDay() {
	d := s.now().Format("2006-01-02")
	if d != s.day {
		s.day, s.blockedToday, s.queriesToday = d, 0, 0
	}
}

// Record counts a query and adds it to the log if the log is on.
func (s *Stats) Record(q Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollDay()
	s.total++
	s.queriesToday++
	if q.Blocked {
		s.totalBlocked++
		s.blockedToday++
	}
	if !s.enabled || len(s.ring) == 0 {
		return
	}
	s.seq++
	q.Seq = s.seq
	if q.Time.IsZero() {
		q.Time = s.now()
	}
	s.ring[s.next] = q
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
}

// Summary is the counter snapshot used by `status`.
type Summary struct {
	BlockedToday int    `json:"blocked_today"`
	QueriesToday int    `json:"queries_today"`
	Total        uint64 `json:"total"`
	TotalBlocked uint64 `json:"total_blocked"`
}

func (s *Stats) Summary() Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollDay()
	return Summary{s.blockedToday, s.queriesToday, s.total, s.totalBlocked}
}

// Recent returns up to n queries newer than since, oldest first.
func (s *Stats) Recent(n int, blockedOnly bool, since uint64) []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Query
	size := len(s.ring)
	count := s.next
	if s.full {
		count = size
	}
	for i := 0; i < count && len(out) < n; i++ {
		idx := (s.next - 1 - i + size) % size
		q := s.ring[idx]
		if q.Seq <= since {
			break
		}
		if blockedOnly && !q.Blocked {
			continue
		}
		out = append(out, q)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// RecentBlockedDomains returns up to n distinct blocked names, newest first,
// for the tray's "Recently blocked" menu.
func (s *Stats) RecentBlockedDomains(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	size := len(s.ring)
	count := s.next
	if s.full {
		count = size
	}
	for i := 0; i < count && len(out) < n; i++ {
		q := s.ring[(s.next-1-i+size)%size]
		if q.Blocked && !seen[q.Name] {
			seen[q.Name] = true
			out = append(out, q.Name)
		}
	}
	return out
}
