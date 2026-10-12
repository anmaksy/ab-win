package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stub struct {
	name  string
	fail  bool
	calls int
}

func (s *stub) Name() string { return s.name }
func (s *stub) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	s.calls++
	if s.fail {
		return nil, errors.New("down")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	return r, nil
}

func TestChainFallbackAndBackoff(t *testing.T) {
	a, b := &stub{name: "a", fail: true}, &stub{name: "b"}
	c := NewChain(a, b)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	m := new(dns.Msg)
	m.SetQuestion("x.com.", dns.TypeA)

	_, name, err := c.Exchange(context.Background(), m)
	if err != nil || name != "b" {
		t.Fatalf("got %q %v", name, err)
	}
	c.Exchange(context.Background(), m)
	if a.calls != 1 {
		t.Fatalf("failed resolver retried during back-off: %d calls", a.calls)
	}
	now = now.Add(backoff + time.Second)
	a.fail = false
	if _, name, _ = c.Exchange(context.Background(), m); name != "a" {
		t.Fatalf("primary not retried after back-off, used %q", name)
	}
}

func TestChainAllDown(t *testing.T) {
	a, b := &stub{name: "a", fail: true}, &stub{name: "b", fail: true}
	c := NewChain(a, b)
	m := new(dns.Msg)
	m.SetQuestion("x.com.", dns.TypeA)
	if _, _, err := c.Exchange(context.Background(), m); err == nil {
		t.Fatal("expected error")
	}
	if a.calls != 1 || b.calls != 1 {
		t.Fatalf("each resolver should be tried once per query: %d %d", a.calls, b.calls)
	}
}

func TestDoHWireFormat(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad type", 415)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil || q.Id != 0 {
			http.Error(w, "bad msg", 400)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		resp.Answer = []dns.RR{rr}
		b, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}))
	defer srv.Close()
	d := &DoH{name: "test", url: srv.URL, client: srv.Client()}
	m := new(dns.Msg)
	m.SetQuestion("x.com.", dns.TypeA)
	m.Id = 4242
	r, err := d.Exchange(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if r.Id != 4242 || len(r.Answer) != 1 {
		t.Fatalf("bad reply %v", r)
	}
}
