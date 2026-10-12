package tray

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestIconsDecode(t *testing.T) {
	dir := os.Getenv("ABWIN_ICON_DIR")
	for _, s := range []int{IconOn, IconOff, IconPaused, IconProblem} {
		ico := Icon(s)
		img, err := png.Decode(bytes.NewReader(ico[22:]))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("icon %d: %v", s, err)
		}
		if dir != "" {
			os.WriteFile(filepath.Join(dir, []string{"on", "off", "paused", "problem"}[s]+".png"), ico[22:], 0o644)
		}
	}
}
