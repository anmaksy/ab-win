package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon states (PLAN 4.2). Shape changes with state, so colour is never the
// only signal.
const (
	IconOn = iota
	IconOff
	IconPaused
	IconProblem
)

var iconColors = map[int]color.RGBA{
	IconOn:      {0x1e, 0x9e, 0x4a, 0xff},
	IconOff:     {0x80, 0x86, 0x8b, 0xff},
	IconPaused:  {0xe0, 0x9a, 0x10, 0xff},
	IconProblem: {0xd3, 0x2f, 0x2f, 0xff},
}

// Icon returns a 32×32 .ico for a state.
func Icon(state int) []byte {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	fill := iconColors[state]
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if inShield(float64(x)+0.5, float64(y)+0.5) {
				img.Set(x, y, fill)
			}
		}
	}
	glyph := func(x, y float64) bool {
		switch state {
		case IconOn: // check mark
			return segDist(x, y, 10, 16.5, 14, 21) < 1.9 || segDist(x, y, 14, 21, 22.5, 11) < 1.9
		case IconPaused: // pause bars
			return (x >= 11 && x <= 14 || x >= 18 && x <= 21) && y >= 9.5 && y <= 21.5
		case IconOff: // dash
			return x >= 10 && x <= 22 && y >= 14.5 && y <= 17.5
		case IconProblem: // exclamation mark
			return (x >= 14.5 && x <= 17.5 && y >= 7.5 && y <= 18) || math.Hypot(x-16, y-22) < 1.9
		}
		return false
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			if inShield(fx, fy) && glyph(fx, fy) {
				img.Set(x, y, white)
			}
		}
	}
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, img)
	return wrapICO(pngBuf.Bytes(), n)
}

// inShield: flat-topped shield narrowing to a point at the bottom.
func inShield(x, y float64) bool {
	const cx, top, mid, bottom, half = 16.0, 2.0, 15.0, 30.5, 12.5
	if y < top || y > bottom {
		return false
	}
	w := half
	if y > mid {
		t := (y - mid) / (bottom - mid)
		w = half * math.Sqrt(1-t*t)
	}
	// Slight notch at the top corners.
	if y < top+2 && math.Abs(x-cx) > w-2+(y-top) {
		return false
	}
	return math.Abs(x-cx) <= w
}

func segDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// wrapICO puts a PNG inside an ICO container (supported since Vista).
func wrapICO(pngData []byte, size int) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&b, le, [3]uint16{0, 1, 1})
	b.WriteByte(byte(size))
	b.WriteByte(byte(size))
	b.WriteByte(0)                   // palette
	b.WriteByte(0)                   // reserved
	binary.Write(&b, le, uint16(1))  // planes
	binary.Write(&b, le, uint16(32)) // bpp
	binary.Write(&b, le, uint32(len(pngData)))
	binary.Write(&b, le, uint32(22))
	b.Write(pngData)
	return b.Bytes()
}
