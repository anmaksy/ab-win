package policy

import (
	"fmt"
	"path/filepath"
	"testing"
)

func buildSnap(domains map[string][]string) *Snapshot {
	b := NewBuilder()
	for list, ds := range domains {
		id := b.AddList(list)
		for _, d := range ds {
			b.Add(id, d)
		}
	}
	for _, ds := range domains {
		for _, d := range ds {
			b.Prune(d)
		}
	}
	return b.Build()
}

func TestSnapshotLookup(t *testing.T) {
	s := buildSnap(map[string][]string{"ads": {"doubleclick.net", "ads.example.com", "x.ads.example.com"}})
	if s.Len() != 2 {
		t.Fatalf("parent-covered entry not removed: len %d", s.Len())
	}
	for _, tc := range []struct {
		name    string
		blocked bool
		matched string
	}{
		{"doubleclick.net", true, "doubleclick.net"},
		{"stats.g.doubleclick.net", true, "doubleclick.net"},
		{"x.ads.example.com", true, "ads.example.com"},
		{"example.com", false, ""},
		{"notdoubleclick.net", false, ""},
		{"net", false, ""},
	} {
		list, m, ok := s.Lookup(tc.name)
		if ok != tc.blocked || m != tc.matched || (ok && list != "ads") {
			t.Errorf("Lookup(%q) = %q %q %v", tc.name, list, m, ok)
		}
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := buildSnap(map[string][]string{"a": {"a.com", "b.com"}})
	p := filepath.Join(t.TempDir(), "lists.bin")
	if err := s.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	s2, err := ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s2.Lookup("x.b.com"); !ok || s2.Len() != 2 {
		t.Fatal("round trip lost data")
	}
}

func TestEnginePrecedence(t *testing.T) {
	e := NewEngine()
	if e.Ready() {
		t.Fatal("ready without snapshot")
	}
	e.SetSnapshot(buildSnap(map[string][]string{"HaGeZi Pro": {"tracker.com", "google.com"}}))
	ba := NewRuleSet()
	ba.Exact["google.com"] = true
	ba.Suffix["safe.com"] = true
	e.SetBuiltinAllow(ba)
	ua, ub := NewRuleSet(), NewRuleSet()
	ua.Suffix["ok.tracker.com"] = true
	ub.Suffix["safe.com"] = true
	ub.Suffix["mine.org"] = true
	e.SetUserRules(ua, ub)

	cases := []struct {
		name    string
		blocked bool
		reason  string
	}{
		{"a.tracker.com", true, "HaGeZi Pro"},
		{"ok.tracker.com", false, ReasonUserAllow},
		{"x.ok.tracker.com", false, ReasonUserAllow},
		{"google.com", false, ReasonBuiltinAllow},    // exact sentinel
		{"adservice.google.com", true, "HaGeZi Pro"}, // exact doesn't cover subdomains
		{"safe.com", true, ReasonUserBlock},          // user block beats built-in allow
		{"a.mine.org", true, ReasonUserBlock},
		{"example.org", false, ""},
	}
	for _, c := range cases {
		d := e.Decide(c.name)
		if d.Blocked != c.blocked || d.Reason != c.reason {
			t.Errorf("Decide(%q) = %+v, want blocked=%v reason=%q", c.name, d, c.blocked, c.reason)
		}
	}
}

func BenchmarkLookup1_5M(b *testing.B) {
	bl := NewBuilder()
	id := bl.AddList("big")
	for i := 0; i < 1_500_000; i++ {
		bl.Add(id, fmt.Sprintf("host%d.domain%d.com", i, i%50000))
	}
	s := bl.Build()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Lookup("a.b.c.notlisted.example.com")
	}
}
