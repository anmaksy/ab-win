// Package cache is an LRU DNS answer cache that honours TTLs and can serve
// stale answers while a refresh runs in the background.
package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxTTL      = 24 * time.Hour
	minTTL      = 10 * time.Second
	negativeTTL = 5 * time.Minute
	// StaleFor is how long after expiry an answer may still be served while refreshing.
	StaleFor = time.Hour
)

type entry struct {
	key     string
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// Cache is safe for concurrent use.
type Cache struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time
}

func New(capacity int) *Cache {
	return &Cache{cap: capacity, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

// Key builds the cache key for a question.
func Key(q dns.Question) string {
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// Get returns a copy of the cached answer with TTLs reduced by its age.
// stale is true when the answer has expired but is within StaleFor.
func (c *Cache) Get(key string) (msg *dns.Msg, stale, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.items[key]
	if !found {
		return nil, false, false
	}
	e := el.Value.(*entry)
	now := c.now()
	if now.After(e.expires.Add(StaleFor)) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false, false
	}
	c.ll.MoveToFront(el)
	m := e.msg.Copy()
	age := uint32(now.Sub(e.stored) / time.Second)
	stale = now.After(e.expires)
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if stale || h.Ttl <= age {
				h.Ttl = 1
			} else {
				h.Ttl -= age
			}
		}
	}
	return m, stale, true
}

// Set stores an upstream answer. Only NOERROR and NXDOMAIN are cached.
func (c *Cache) Set(key string, m *dns.Msg) {
	if m == nil || m.Truncated || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return
	}
	ttl := ttlOf(m)
	if ttl <= 0 {
		return
	}
	now := c.now()
	e := &entry{key: key, msg: m.Copy(), stored: now, expires: now.Add(ttl)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(e)
	for c.ll.Len() > c.cap {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.items, old.Value.(*entry).key)
	}
}

// Flush empties the cache.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.items = map[string]*list.Element{}
	c.mu.Unlock()
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func ttlOf(m *dns.Msg) time.Duration {
	var min uint32 = ^uint32(0)
	found := false
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
		found = true
	}
	if !found {
		// Negative answer: SOA minimum (RFC 2308), else a default.
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				t := soa.Minttl
				if soa.Hdr.Ttl < t {
					t = soa.Hdr.Ttl
				}
				d := time.Duration(t) * time.Second
				return clamp(d, minTTL, negativeTTL)
			}
		}
		return minTTL
	}
	return clamp(time.Duration(min)*time.Second, minTTL, maxTTL)
}

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
