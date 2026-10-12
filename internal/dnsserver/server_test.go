package dnsserver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/anmaksy/ab-win/internal/cache"
	"github.com/anmaksy/ab-win/internal/policy"
	"github.com/anmaksy/ab-win/internal/stats"
)

// fakeUpstream answers A queries with 192.0.2.1, except names in cname,
// which get a CNAME to the mapped target first.
type fakeUpstream struct {
	cname map[string]string
	calls atomic.Int32
	fail  bool
	big   bool
}

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	f.calls.Add(1)
	if f.fail {
		return nil, "", errors.New("down")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	q := m.Question[0]
	name := q.Name
	if t, ok := f.cname[name]; ok {
		r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: t})
		name = t
	}
	if q.Qtype == dns.TypeA {
		n := 1
		if f.big {
			n = 60
		}
		for i := 0; i < n; i++ {
			r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, byte(i+1))})
		}
	}
	return r, "fake", nil
}

func newTestServer(t *testing.T, up *fakeUpstream) *Server {
	t.Helper()
	e := policy.NewEngine()
	b := policy.NewBuilder()
	id := b.AddList("Test ads list")
	b.Add(id, "doubleclick.net")
	b.Add(id, "eulerian.net")
	e.SetSnapshot(b.Build())
	ua := policy.NewRuleSet()
	ua.Suffix["allowed.doubleclick.net"] = true
	e.SetUserRules(ua, policy.NewRuleSet())
	s := &Server{Engine: e, Cache: cache.New(100), Stats: stats.New(100, true), Logf: t.Logf}
	s.SetUpstream(up, nil)
	s.SetFiltering(true)
	s.SetCNAMECheck(true)
	if err := s.Listen([]string{"127.0.0.1:0"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return s
}

func query(t *testing.T, s *Server, name string, qtype uint16, network string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network}
	addr := s.Addr()
	if network == "tcp" {
		for _, srv := range s.servers {
			if srv.Listener != nil {
				addr = srv.Listener.Addr().String()
			}
		}
	}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return r
}

func isBlockedA(r *dns.Msg) bool {
	return len(r.Answer) == 1 && r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) && r.Answer[0].Header().Ttl == BlockTTL
}

func TestBlockAndAllow(t *testing.T) {
	up := &fakeUpstream{}
	s := newTestServer(t, up)

	if r := query(t, s, "stats.g.doubleclick.net", dns.TypeA, "udp"); !isBlockedA(r) {
		t.Fatalf("A not blocked: %v", r)
	}
	r := query(t, s, "ad.doubleclick.net", dns.TypeAAAA, "udp")
	if len(r.Answer) != 1 || !r.Answer[0].(*dns.AAAA).AAAA.Equal(net.IPv6zero) {
		t.Fatalf("AAAA not blocked: %v", r)
	}
	r = query(t, s, "ad.doubleclick.net", dns.TypeHTTPS, "udp")
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("HTTPS should be empty NOERROR: %v", r)
	}
	if up.calls.Load() != 0 {
		t.Fatal("blocked names must not reach upstream")
	}
	if r := query(t, s, "allowed.doubleclick.net", dns.TypeA, "udp"); isBlockedA(r) || len(r.Answer) != 1 {
		t.Fatalf("user allowlist ignored: %v", r)
	}
	if r := query(t, s, "example.com", dns.TypeA, "tcp"); len(r.Answer) != 1 {
		t.Fatalf("TCP forward failed: %v", r)
	}
	if sum := s.Stats.Summary(); sum.BlockedToday != 3 {
		t.Fatalf("blocked today = %d", sum.BlockedToday)
	}
}

func TestPauseForwardsEverything(t *testing.T) {
	s := newTestServer(t, &fakeUpstream{})
	s.SetFiltering(false)
	if r := query(t, s, "doubleclick.net", dns.TypeA, "udp"); isBlockedA(r) {
		t.Fatal("blocked while paused")
	}
	// The test domain answers blocked in every state, so doctor can probe routing.
	if r := query(t, s, TestDomain, dns.TypeA, "udp"); !isBlockedA(r) {
		t.Fatal("test domain not answered")
	}
}

func TestNotReadyForwardsUnfiltered(t *testing.T) {
	s := newTestServer(t, &fakeUpstream{})
	s.Engine.SetSnapshot(nil)
	if r := query(t, s, "doubleclick.net", dns.TypeA, "udp"); isBlockedA(r) {
		t.Fatal("must not filter before lists load")
	}
}

func TestCNAMEUncloaking(t *testing.T) {
	up := &fakeUpstream{cname: map[string]string{"metrics.shop.com.": "shop.eulerian.net."}}
	s := newTestServer(t, up)
	r := query(t, s, "metrics.shop.com", dns.TypeA, "udp")
	if !isBlockedA(r) {
		t.Fatalf("CNAME-cloaked tracker not blocked: %v", r)
	}
	q := s.Stats.Recent(1, true, 0)
	if len(q) != 1 || q[0].Reason != "Test ads list (hidden behind shop.eulerian.net)" {
		t.Fatalf("reason = %+v", q)
	}
	s.SetCNAMECheck(false)
	if r := query(t, s, "metrics.shop.com", dns.TypeA, "udp"); isBlockedA(r) {
		t.Fatal("CNAME check off but still blocked")
	}
}

func TestFirefoxCanary(t *testing.T) {
	s := newTestServer(t, &fakeUpstream{})
	if r := query(t, s, FirefoxCanary, dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("canary rcode %d", r.Rcode)
	}
}

func TestCacheHit(t *testing.T) {
	up := &fakeUpstream{}
	s := newTestServer(t, up)
	query(t, s, "example.com", dns.TypeA, "udp")
	query(t, s, "EXAMPLE.com", dns.TypeA, "udp")
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls.Load())
	}
}

func TestUpstreamFailureIsServfail(t *testing.T) {
	s := newTestServer(t, &fakeUpstream{fail: true})
	if r := query(t, s, "example.com", dns.TypeA, "udp"); r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode %d", r.Rcode)
	}
}

func TestUDPTruncationAndTCPRetry(t *testing.T) {
	s := newTestServer(t, &fakeUpstream{big: true})
	m := new(dns.Msg)
	m.SetQuestion("big.example.com.", dns.TypeA)
	c := &dns.Client{Net: "udp"}
	r, _, err := c.Exchange(m, s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated {
		t.Fatalf("expected TC bit for a %d-record answer over 512-byte UDP", len(r.Answer))
	}
	if r := query(t, s, "big.example.com", dns.TypeA, "tcp"); len(r.Answer) != 60 {
		t.Fatalf("TCP got %d answers", len(r.Answer))
	}
}

func TestLocalNames(t *testing.T) {
	for name, want := range map[string]bool{
		"fritz.box": true, "nas.lan": true, "printer": true, "x.home.arpa": true,
		"1.1.168.192.in-addr.arpa": true, "5.0.20.172.in-addr.arpa": true,
		"example.com": false, "8.8.8.8.in-addr.arpa": false, "corp.example.com": false,
		"pc.mycorp.example": true,
	} {
		if got := isLocalName(name, []string{"mycorp.example"}); got != want {
			t.Errorf("isLocalName(%q) = %v", name, got)
		}
	}
}

func FuzzServeDNS(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("ads.doubleclick.net.", dns.TypeA)
	b, _ := m.Pack()
	f.Add(b)
	s := &Server{Engine: policy.NewEngine(), Cache: cache.New(10), Stats: stats.New(10, true)}
	s.SetUpstream(&fakeUpstream{}, nil)
	s.SetFiltering(true)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := new(dns.Msg)
		if err := r.Unpack(data); err != nil {
			return
		}
		s.ServeDNS(&nopWriter{}, r)
	})
}

type nopWriter struct{ dns.ResponseWriter }

func (*nopWriter) WriteMsg(m *dns.Msg) error { _, err := m.Pack(); return err }
func (*nopWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
