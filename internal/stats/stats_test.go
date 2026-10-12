package stats

import "testing"

func TestRingAndRecentBlocked(t *testing.T) {
	s := New(3, true)
	for _, q := range []Query{
		{Name: "a.com", Blocked: true}, {Name: "b.com"}, {Name: "a.com", Blocked: true},
		{Name: "c.com", Blocked: true}, {Name: "d.com"},
	} {
		s.Record(q)
	}
	r := s.Recent(10, false, 0)
	if len(r) != 3 || r[0].Name != "a.com" || r[2].Name != "d.com" {
		t.Fatalf("ring = %+v", r)
	}
	if got := s.Recent(10, false, r[1].Seq); len(got) != 1 || got[0].Name != "d.com" {
		t.Fatalf("since filter = %+v", got)
	}
	if d := s.RecentBlockedDomains(10); len(d) != 2 || d[0] != "c.com" || d[1] != "a.com" {
		t.Fatalf("recent blocked = %v", d)
	}
	if sum := s.Summary(); sum.BlockedToday != 3 || sum.QueriesToday != 5 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestLogOff(t *testing.T) {
	s := New(10, false)
	s.Record(Query{Name: "a.com", Blocked: true})
	if len(s.Recent(10, false, 0)) != 0 || s.Summary().BlockedToday != 1 {
		t.Fatal("query log off must still count but not store names")
	}
}
