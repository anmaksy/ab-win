package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anmaksy/ab-win/internal/catalog"
)

func list(n int, extra ...string) []byte {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "ad%d.example.com\n", i)
	}
	for _, e := range extra {
		sb.WriteString(e + "\n")
	}
	return []byte(sb.String())
}

func TestCheck(t *testing.T) {
	u := &Updater{Sentinels: []string{"google.com"}}
	if _, err := u.Check(list(100), 10, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Check(list(5), 10, 0); !errors.Is(err, ErrTooSmall) {
		t.Fatalf("want ErrTooSmall, got %v", err)
	}
	if _, err := u.Check(list(40), 10, 100); !errors.Is(err, ErrShrunk) {
		t.Fatalf("want ErrShrunk, got %v", err)
	}
	if _, err := u.Check(list(401), 10, 100); !errors.Is(err, ErrGrew) {
		t.Fatalf("want ErrGrew, got %v", err)
	}
	if _, err := u.Check(list(100, "google.com"), 10, 0); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("want ErrPoisoned, got %v", err)
	}
	// A subdomain of a sentinel is fine (sentinels are exact).
	if _, err := u.Check(list(100, "adservice.google.com"), 10, 0); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateAllKeepsLastGood(t *testing.T) {
	body := list(200)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` && string(body) == string(list(200)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()
	u := &Updater{Dir: dir, Client: srv.Client(), Logf: t.Logf}
	src := []catalog.Source{{ID: "test", Name: "Test", URL: srv.URL, MinSize: 10}}

	changed, errs := u.UpdateAll(context.Background(), src)
	if !changed || len(errs) != 0 {
		t.Fatalf("first fetch: changed=%v errs=%v", changed, errs)
	}
	changed, errs = u.UpdateAll(context.Background(), src)
	if changed || len(errs) != 0 {
		t.Fatalf("304 fetch: changed=%v errs=%v", changed, errs)
	}
	body = list(20) // shrinks by 90%: must be rejected
	changed, errs = u.UpdateAll(context.Background(), src)
	if changed || len(errs) != 1 || !errors.Is(errs[0], ErrShrunk) {
		t.Fatalf("shrunk fetch: changed=%v errs=%v", changed, errs)
	}
	if m := u.LoadMeta()["test"]; m.Count != 200 || m.LastError == "" {
		t.Fatalf("meta = %+v", m)
	}
}

func TestCompileUsesSeedsAndCategories(t *testing.T) {
	s, err := Compile(t.TempDir(), "balanced", map[string]bool{"ads": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Lookup("stats.g.doubleclick.net"); !ok {
		t.Fatal("seed ads list not compiled")
	}
	s, _ = Compile(t.TempDir(), "balanced", map[string]bool{"ads": false})
	if _, _, ok := s.Lookup("doubleclick.net"); ok {
		t.Fatal("disabled category still blocks")
	}
}

func TestBuiltinAllow(t *testing.T) {
	r, sentinels := BuiltinAllow()
	if !r.Suffix["msftconnecttest.com"] || !r.Exact["google.com"] || len(sentinels) == 0 {
		t.Fatalf("builtin allowlist not loaded: %d sentinels", len(sentinels))
	}
}
