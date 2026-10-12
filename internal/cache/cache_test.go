package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func answer(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A 192.0.2.1", name, ttl))
	m.Answer = []dns.RR{rr}
	return m
}

func TestTTLAgingAndStale(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(10)
	c.now = func() time.Time { return now }
	k := Key(dns.Question{Name: "a.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	c.Set(k, answer("a.com.", 300))

	now = now.Add(100 * time.Second)
	m, stale, ok := c.Get(k)
	if !ok || stale || m.Answer[0].Header().Ttl != 200 {
		t.Fatalf("got ok=%v stale=%v ttl=%d", ok, stale, m.Answer[0].Header().Ttl)
	}
	now = now.Add(250 * time.Second)
	m, stale, ok = c.Get(k)
	if !ok || !stale || m.Answer[0].Header().Ttl != 1 {
		t.Fatalf("expected stale answer, got ok=%v stale=%v", ok, stale)
	}
	now = now.Add(StaleFor)
	if _, _, ok = c.Get(k); ok {
		t.Fatal("expected eviction after stale window")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(2)
	for _, n := range []string{"a.com.", "b.com.", "c.com."} {
		c.Set(Key(dns.Question{Name: n, Qtype: dns.TypeA, Qclass: dns.ClassINET}), answer(n, 60))
	}
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
	if _, _, ok := c.Get(Key(dns.Question{Name: "a.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})); ok {
		t.Fatal("oldest entry not evicted")
	}
}

func TestNoCacheServfail(t *testing.T) {
	c := New(2)
	m := answer("a.com.", 60)
	m.Rcode = dns.RcodeServerFailure
	c.Set("k", m)
	if c.Len() != 0 {
		t.Fatal("SERVFAIL cached")
	}
}
