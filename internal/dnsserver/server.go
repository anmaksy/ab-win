// Package dnsserver is the loopback DNS listener: it applies the policy,
// answers blocked names with 0.0.0.0 / ::, un-cloaks CNAME trackers, caches,
// and forwards everything else upstream.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/anmaksy/ab-win/internal/cache"
	"github.com/anmaksy/ab-win/internal/domain"
	"github.com/anmaksy/ab-win/internal/policy"
	"github.com/anmaksy/ab-win/internal/stats"
	"github.com/anmaksy/ab-win/internal/upstream"
)

const (
	// BlockTTL is the TTL of blocked answers (PLAN section 3.2).
	BlockTTL = 60
	// TestDomain always gets a blocked answer, whatever the state. `doctor`
	// resolves it through Windows to prove DNS really reaches us.
	TestDomain = "blocked.ab-win.test"
	// FirefoxCanary disables Firefox's default DoH when answered with NXDOMAIN.
	FirefoxCanary = "use-application-dns.net"
)

// Forwarder is the upstream chain.
type Forwarder interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error)
}

// Server handles DNS queries.
type Server struct {
	Engine *policy.Engine
	Cache  *cache.Cache
	Stats  *stats.Stats
	Logf   func(string, ...any)

	mu         sync.RWMutex
	upstream   Forwarder
	local      upstream.Resolver // the network's own DNS, for local names
	filtering  bool
	cnameCheck bool
	searchDoms []string

	inflight sync.Map // cache key -> struct{}, for background stale refresh
	servers  []*dns.Server
}

// SetUpstream swaps the upstream chain (config change).
func (s *Server) SetUpstream(f Forwarder, local upstream.Resolver) {
	s.mu.Lock()
	s.upstream, s.local = f, local
	s.mu.Unlock()
	s.Cache.Flush()
}

// SetFiltering turns blocking on or off (on/off/pause). DNS keeps flowing either way.
func (s *Server) SetFiltering(on bool) {
	s.mu.Lock()
	s.filtering = on
	s.mu.Unlock()
}

func (s *Server) Filtering() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filtering
}

func (s *Server) SetCNAMECheck(on bool) {
	s.mu.Lock()
	s.cnameCheck = on
	s.mu.Unlock()
}

// SetSearchDomains sets the network's DNS suffixes (from DHCP); names under
// them are resolved by the network's own DNS.
func (s *Server) SetSearchDomains(d []string) {
	s.mu.Lock()
	s.searchDoms = d
	s.mu.Unlock()
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Listen binds UDP and TCP on each address and serves in the background.
// IPv6 loopback failing to bind (IPv6 disabled) is not fatal.
func (s *Server) Listen(addrs []string) error {
	bound := 0
	var firstErr error
	for _, a := range addrs {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		l, err := net.Listen("tcp", a)
		if err != nil {
			pc.Close()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		udp := &dns.Server{PacketConn: pc, Handler: s, UDPSize: 65535}
		tcp := &dns.Server{Listener: l, Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		s.servers = append(s.servers, udp, tcp)
		go udp.ActivateAndServe()
		go tcp.ActivateAndServe()
		bound++
	}
	if bound == 0 {
		return firstErr
	}
	return nil
}

// Addr returns the UDP address of the first listener (tests use port 0).
func (s *Server) Addr() string {
	for _, srv := range s.servers {
		if srv.PacketConn != nil {
			return srv.PacketConn.LocalAddr().String()
		}
	}
	return ""
}

func (s *Server) Shutdown() {
	for _, srv := range s.servers {
		srv.Shutdown()
	}
	s.servers = nil
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	resp, q := s.handle(r)
	if resp == nil {
		return
	}
	resp.Id = r.Id
	resp.Response = true
	resp.RecursionDesired = r.RecursionDesired
	resp.RecursionAvailable = true
	if len(r.Question) > 0 {
		resp.Question = r.Question[:1]
	}
	clientOpt := r.IsEdns0()
	resp.Extra = stripOPT(resp.Extra)
	size := dns.MinMsgSize
	if clientOpt != nil {
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(1232)
		o.SetDo(clientOpt.Do())
		if q.ede != nil {
			o.Option = append(o.Option, q.ede)
		}
		resp.Extra = append(resp.Extra, o)
		if us := int(clientOpt.UDPSize()); us > size {
			size = us
		}
	}
	if w.RemoteAddr() != nil && w.RemoteAddr().Network() == "udp" {
		resp.Truncate(size)
	} else {
		resp.Truncate(dns.MaxMsgSize)
	}
	w.WriteMsg(resp)
	if q.name != "" && s.Stats != nil {
		s.Stats.Record(stats.Query{
			Name: q.name, Type: q.qtype, Blocked: q.blocked, Reason: q.reason,
			Cached: q.cached, Upstream: q.upstream,
			Millis: float64(time.Since(start).Microseconds()) / 1000,
		})
	}
}

type queryInfo struct {
	name, qtype, reason, upstream string
	blocked, cached               bool
	ede                           *dns.EDNS0_EDE
}

func (s *Server) handle(r *dns.Msg) (*dns.Msg, queryInfo) {
	var qi queryInfo
	if r.Response || r.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		return m, qi
	}
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		return m, qi
	}
	q := r.Question[0]
	name := domain.NormalizeQuery(q.Name)
	qi.name, qi.qtype = name, dns.TypeToString[q.Qtype]
	if qi.qtype == "" {
		qi.qtype = fmt.Sprint(q.Qtype)
	}

	if name == TestDomain || strings.HasSuffix(name, "."+TestDomain) {
		qi.blocked, qi.reason = true, "ab-win test domain"
		return blockResponse(r), qi
	}
	if name == FirefoxCanary || strings.HasSuffix(name, "."+FirefoxCanary) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		qi.reason = "Firefox DoH canary"
		return m, qi
	}

	s.mu.RLock()
	filtering, cnameCheck, search := s.filtering, s.cnameCheck, s.searchDoms
	fwd, local := s.upstream, s.local
	s.mu.RUnlock()

	if isLocalName(name, search) {
		qi.upstream = "network DNS (local name)"
		return s.forwardLocal(r, local), qi
	}

	// Until lists are loaded we forward unfiltered: our startup must never
	// cut the network off.
	filtering = filtering && s.Engine.Ready()
	if filtering {
		if d := s.Engine.Decide(name); d.Blocked {
			qi.blocked, qi.reason = true, d.Reason
			qi.ede = &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: d.Reason}
			return blockResponse(r), qi
		}
	}

	key := cache.Key(q)
	resp, stale, ok := s.Cache.Get(key)
	if ok {
		qi.cached = true
		if stale {
			s.refresh(key, r, fwd)
		}
	} else {
		var err error
		resp, qi.upstream, err = s.forward(r, fwd)
		if err != nil {
			s.logf("upstream failed for %s: %v", name, err)
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			return m, qi
		}
		s.Cache.Set(key, resp)
	}

	if filtering && cnameCheck && !s.Engine.UserAllowed(name) {
		for _, rr := range resp.Answer {
			c, isCNAME := rr.(*dns.CNAME)
			if !isCNAME {
				continue
			}
			target := domain.NormalizeQuery(c.Target)
			if d := s.Engine.Decide(target); d.Blocked {
				qi.blocked = true
				qi.reason = fmt.Sprintf("%s (hidden behind %s)", d.Reason, target)
				qi.ede = &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: qi.reason}
				return blockResponse(r), qi
			}
		}
	}
	return resp, qi
}

func (s *Server) forward(r *dns.Msg, fwd Forwarder) (*dns.Msg, string, error) {
	if fwd == nil {
		return nil, "", errors.New("no upstream configured")
	}
	m := upstreamQuery(r)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return fwd.Exchange(ctx, m)
}

func (s *Server) forwardLocal(r *dns.Msg, local upstream.Resolver) *dns.Msg {
	if local != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if resp, err := local.Exchange(ctx, upstreamQuery(r)); err == nil {
			return resp
		}
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNameError)
	return m
}

func (s *Server) refresh(key string, r *dns.Msg, fwd Forwarder) {
	if _, busy := s.inflight.LoadOrStore(key, struct{}{}); busy {
		return
	}
	rc := r.Copy()
	go func() {
		defer s.inflight.Delete(key)
		if resp, _, err := s.forward(rc, fwd); err == nil {
			s.Cache.Set(key, resp)
		}
	}()
}

// upstreamQuery builds a clean query for the question, asking for DNSSEC data
// if the client did.
func upstreamQuery(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.CheckingDisabled = r.CheckingDisabled
	m.Question = []dns.Question{r.Question[0]}
	do := false
	if o := r.IsEdns0(); o != nil {
		do = o.Do()
	}
	m.SetEdns0(1232, do)
	return m
}

func blockResponse(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	q := r.Question[0]
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: BlockTTL}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero.To4()}}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
	default:
		// HTTPS/SVCB and everything else: empty NOERROR, so no ECH or
		// alt-svc hints leak for a blocked name.
	}
	return m
}

func stripOPT(rrs []dns.RR) []dns.RR {
	out := rrs[:0:0]
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

// Local zones go to the network's own DNS: home routers (fritz.box, .lan),
// mDNS-style names, and private reverse lookups. Sending these to Cloudflare
// would just fail and leak LAN names.
var localSuffixes = []string{
	"local", "lan", "home", "internal", "intranet", "private", "corp", "localdomain",
	"home.arpa", "box",
	"10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
	"d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
}

func init() {
	for i := 16; i <= 31; i++ {
		localSuffixes = append(localSuffixes, fmt.Sprintf("%d.172.in-addr.arpa", i))
	}
}

func isLocalName(name string, search []string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return name != "" // single-label names
	}
	for _, suf := range localSuffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	for _, suf := range search {
		if suf != "" && (name == suf || strings.HasSuffix(name, "."+suf)) {
			return true
		}
	}
	return false
}
