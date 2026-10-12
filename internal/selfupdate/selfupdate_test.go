package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.2.3", "v1.2.2", true},
		{"v1.10.0", "v1.9.9", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v2.0.0", false},
		{"v2.0.0-rc1", "v1.9.0", true},
		{"v9.9.9", "dev", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestDownloadVerifiesChecksum(t *testing.T) {
	bin := []byte("new binary")
	sum := sha256.Sum256(bin)
	sums := hex.EncodeToString(sum[:]) + "  " + AssetName() + "\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			w.Write(bin)
		case "/sums":
			w.Write([]byte(sums))
		case "/badsums":
			w.Write([]byte("0000  " + AssetName() + "\n"))
		}
	}))
	defer srv.Close()
	rel := Release{Tag: "v1.0.0", Assets: []Asset{{Name: AssetName(), URL: srv.URL + "/bin"}, {Name: "SHA256SUMS", URL: srv.URL + "/sums"}}}
	got, err := Download(context.Background(), srv.Client(), rel)
	if err != nil || string(got) != string(bin) {
		t.Fatalf("download: %q %v", got, err)
	}
	rel.Assets[1].URL = srv.URL + "/badsums"
	if _, err := Download(context.Background(), srv.Client(), rel); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
}

func TestSwapKeepsOld(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "ab-win.exe")
	os.WriteFile(exe, []byte("old"), 0o755)
	if err := Swap(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatal("not swapped")
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "old" {
		t.Fatal("old binary not kept for rollback")
	}
}
