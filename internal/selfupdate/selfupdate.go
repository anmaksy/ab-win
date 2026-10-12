// Package selfupdate checks this repo's GitHub Releases and swaps in a
// newer binary after verifying its SHA-256 against the release's SHA256SUMS.
package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Release is the part of the GitHub API response we use.
type Release struct {
	Tag    string  `json:"tag_name"`
	URL    string  `json:"html_url"`
	Assets []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// AssetName is the binary for this machine: ab-win.exe is amd64 (what
// friends click on), ab-win-arm64.exe is for ARM PCs.
func AssetName() string {
	if runtime.GOARCH == "arm64" {
		return "ab-win-arm64.exe"
	}
	return "ab-win.exe"
}

// API is the GitHub API base URL (tests override it).
var API = "https://api.github.com"

// Latest fetches the latest published release.
func Latest(ctx context.Context, c *http.Client, repo string) (Release, error) {
	var r Release
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, API+"/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
	return r, err
}

// Newer reports whether tag a is a newer version than b ("v1.2.3" form).
// A "dev" build never auto-updates.
func Newer(a, b string) bool {
	if b == "dev" || b == "" {
		return false
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parse(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

const maxBinary = 100 << 20

// Download fetches this machine's asset from rel and verifies its checksum.
func Download(ctx context.Context, c *http.Client, rel Release) ([]byte, error) {
	var bin, sums *Asset
	for i := range rel.Assets {
		switch rel.Assets[i].Name {
		case AssetName():
			bin = &rel.Assets[i]
		case "SHA256SUMS":
			sums = &rel.Assets[i]
		}
	}
	if bin == nil || sums == nil {
		return nil, fmt.Errorf("release %s has no %s or SHA256SUMS", rel.Tag, AssetName())
	}
	sumsBody, err := get(ctx, c, sums.URL, 1<<20)
	if err != nil {
		return nil, err
	}
	want := ""
	sc := bufio.NewScanner(bytes.NewReader(sumsBody))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == bin.Name {
			want = strings.ToLower(f[0])
		}
	}
	if want == "" {
		return nil, fmt.Errorf("SHA256SUMS has no entry for %s", bin.Name)
	}
	body, err := get(ctx, c, bin.URL, maxBinary)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("downloaded binary does not match SHA256SUMS; not installing it")
	}
	return body, nil
}

func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("refusing non-HTTPS download")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("download too large")
	}
	return b, err
}

// Swap replaces exe with newBinary, keeping the old one as exe.old for
// rollback. Windows allows renaming a running executable.
func Swap(exe string, newBinary []byte) error {
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, newBinary, 0o755); err != nil {
		return err
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		return err
	}
	return nil
}
