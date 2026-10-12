package lists

import (
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		line string
		want []Entry
	}{
		{"", nil},
		{"# comment", nil},
		{"! abp comment", nil},
		{"[Adblock Plus 2.0]", nil},
		{"ads.example.com", []Entry{{Domain: "ads.example.com"}}},
		{"  Ads.Example.COM.  ", []Entry{{Domain: "ads.example.com"}}},
		{"ads.example.com # inline", []Entry{{Domain: "ads.example.com"}}},
		{"*.ads.example.com", []Entry{{Domain: "ads.example.com"}}},
		{"0.0.0.0 ads.example.com", []Entry{{Domain: "ads.example.com"}}},
		{"127.0.0.1\tads.example.com", []Entry{{Domain: "ads.example.com"}}},
		{"0.0.0.0 a.example.com b.example.com #c", []Entry{{Domain: "a.example.com"}, {Domain: "b.example.com"}}},
		{"::1 ads.example.com", []Entry{{Domain: "ads.example.com"}}},
		{"127.0.0.1 localhost", nil},
		{"0.0.0.0 0.0.0.0", nil},
		{"::1 ip6-localhost", nil},
		{"||ads.example.com^", []Entry{{Domain: "ads.example.com"}}},
		{"||ads.example.com^$important", []Entry{{Domain: "ads.example.com"}}},
		{"@@||good.example.com^", []Entry{{Domain: "good.example.com", Allow: true}}},
		{"||ads.example.com^$third-party", nil},
		{"||example.com/ads/*", nil},
		{"||ads.*.com^", nil},
		{"example.com##.ad-banner", nil},
		{"/banner[0-9]+/", nil},
		{"=google.com", []Entry{{Domain: "google.com", Exact: true}}},
		{"localhost", nil},
		{"com", nil},
		{"-bad.example.com", nil},
		{"bad-.example.com", nil},
		{"under_score.example.com", []Entry{{Domain: "under_score.example.com"}}},
		{"bücher.example", []Entry{{Domain: "xn--bcher-kva.example"}}},
		{strings.Repeat("a", 64) + ".com", nil},
		{"two words", nil},
	}
	for _, tt := range tests {
		got := ParseLine(tt.line)
		if len(got) != len(tt.want) {
			t.Errorf("ParseLine(%q) = %v, want %v", tt.line, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParseLine(%q)[%d] = %+v, want %+v", tt.line, i, got[i], tt.want[i])
			}
		}
	}
}

func TestParseBOMAndCRLF(t *testing.T) {
	in := "\ufeffads.example.com\r\n# c\r\ntrack.example.net\r\n"
	var got []string
	if err := Parse(strings.NewReader(in), func(e Entry) { got = append(got, e.Domain) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "ads.example.com" || got[1] != "track.example.net" {
		t.Fatalf("got %v", got)
	}
}

func FuzzParseLine(f *testing.F) {
	for _, s := range []string{"ads.example.com", "0.0.0.0 a.b", "||x.y^", "@@||x.y^$important", "=a.b", "*.a.b", "bücher.de"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, e := range ParseLine(s) {
			if e.Domain == "" || len(e.Domain) > 253 || strings.ToLower(e.Domain) != e.Domain || !strings.Contains(e.Domain, ".") {
				t.Fatalf("bad entry %+v from %q", e, s)
			}
		}
	})
}
