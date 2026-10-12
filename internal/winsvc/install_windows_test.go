//go:build windows

package winsvc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDelayedRemoveDirWithSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Program Files", "ab-win")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ab-win.exe"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "ab-win.exe.old"), []byte("x"), 0o644)
	if err := delayedRemoveDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s still exists", dir)
}
