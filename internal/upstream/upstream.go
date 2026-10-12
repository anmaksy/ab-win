// Package upstream forwards allowed queries: DNS-over-HTTPS to Cloudflare
// (malware-blocking 1.1.1.2 by default) with Quad9 as the fallback, and plain
// DNS to the network's own servers as a last resort (captive portals,
// networks that block DoH) and for local names.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver forwards one query.
type Resolver interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	Name() string
}

// DoH is an RFC 8484 client that dials fixed bootstrap IPs, so it never
// needs DNS to find its own server.
type DoH struct {
	name   string
	url    string
	client *http.Client
}

// NewDoH creates a DoH client for url whose host is reached at the given IPs.
func NewDoH(name, url string, bootstrap []string) *DoH {
	var mu sync.Mutex
	next := 0
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			var lastErr error
			mu.Lock()
			start := next
			mu.Unlock()
			for i := range bootstrap {
				ip := bootstrap[(start+i)%len(bootstrap)]
				c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
				if err == nil {
					mu.Lock()
					next = (start + i) % len(bootstrap)
					mu.Unlock()
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 4 * time.Second,
	}
	return &DoH{name: name, url: url, client: &http.Client{Transport: tr, Timeout: 5 * time.Second}}
}

func (d *DoH) Name() string { return d.name }

func (d *DoH) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 recommends 0 for cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", d.name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = m.Id
	return r, nil
}

// Plain sends classic DNS over UDP (TCP on truncation) to servers returned by
// a function, so the list can follow network changes.
type Plain struct {
	name    string
	servers func() []string
}

func NewPlain(name string, servers func() []string) *Plain {
	return &Plain{name: name, servers: servers}
}

func (p *Plain) Name() string { return p.name }

var ErrNoServers = errors.New("no network DNS servers known")

func (p *Plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	servers := p.servers()
	if len(servers) == 0 {
		return nil, ErrNoServers
	}
	var lastErr error
	for _, s := range servers {
		addr := net.JoinHostPort(s, "53")
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, addr)
		if err == nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, m, addr)
		}
		if err == nil {
			return r, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Chain tries resolvers in order. A resolver that fails is skipped for a short
// back-off so one dead upstream doesn't add latency to every query.
type Chain struct {
	resolvers []Resolver
	mu        sync.Mutex
	downUntil []time.Time
	now       func() time.Time
}

func NewChain(rs ...Resolver) *Chain {
	return &Chain{resolvers: rs, downUntil: make([]time.Time, len(rs)), now: time.Now}
}

const backoff = 30 * time.Second

// Exchange returns the first successful answer and the name of the resolver that gave it.
func (c *Chain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	var errs []error
	tried := make([]bool, len(c.resolvers))
	for pass := 0; pass < 2; pass++ {
		for i, r := range c.resolvers {
			c.mu.Lock()
			down := c.now().Before(c.downUntil[i])
			c.mu.Unlock()
			// First pass skips resolvers in back-off; the second pass tries
			// them anyway rather than fail the query.
			if tried[i] || (pass == 0 && down) {
				continue
			}
			tried[i] = true
			ctx2, cancel := context.WithTimeout(ctx, 4*time.Second)
			resp, err := r.Exchange(ctx2, m)
			cancel()
			if err == nil && resp.Rcode != dns.RcodeServerFailure {
				c.mu.Lock()
				c.downUntil[i] = time.Time{}
				c.mu.Unlock()
				return resp, r.Name(), nil
			}
			if err == nil {
				err = fmt.Errorf("%s: SERVFAIL", r.Name())
			}
			errs = append(errs, err)
			c.mu.Lock()
			c.downUntil[i] = c.now().Add(backoff)
			c.mu.Unlock()
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
		}
	}
	return nil, "", errors.Join(errs...)
}

// Names lists the resolvers in order.
func (c *Chain) Names() []string {
	var out []string
	for _, r := range c.resolvers {
		out = append(out, r.Name())
	}
	return out
}

// Profiles for the `upstream` config setting.
var (
	CloudflareSecurity = func() *DoH {
		return NewDoH("Cloudflare (malware-blocking)", "https://security.cloudflare-dns.com/dns-query",
			[]string{"1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"})
	}
	Cloudflare = func() *DoH {
		return NewDoH("Cloudflare", "https://cloudflare-dns.com/dns-query",
			[]string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"})
	}
	Quad9 = func() *DoH {
		return NewDoH("Quad9", "https://dns.quad9.net/dns-query",
			[]string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"})
	}
)

// ForProfile builds the resolver chain for a config value. system is the
// network's own DNS, used as the last resort everywhere.
func ForProfile(profile string, system Resolver) *Chain {
	switch profile {
	case "system":
		return NewChain(system)
	case "cloudflare":
		return NewChain(Cloudflare(), Quad9(), system)
	case "quad9":
		return NewChain(Quad9(), CloudflareSecurity(), system)
	default:
		return NewChain(CloudflareSecurity(), Quad9(), system)
	}
}
