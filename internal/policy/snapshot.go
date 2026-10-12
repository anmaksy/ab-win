// Package policy decides whether a name is blocked. Compiled lists are kept as
// a sorted array of 64-bit domain hashes with a parallel array of list ids,
// so 1.5M domains take about 15 MB and a lookup is O(labels × log n).
package policy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/anmaksy/ab-win/internal/domain"
)

// Snapshot is an immutable compiled blocklist.
type Snapshot struct {
	Lists  []string // list display names, indexed by source id
	hashes []uint64
	src    []uint16
}

// Len is the number of domains in the snapshot.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.hashes)
}

// Hash is the domain hash used by snapshots.
// It is FNV-1a 64, written inline so lookups don't allocate.
func Hash(d string) uint64 {
	const offset, prime = 14695981039346656037, 1099511628211
	h := uint64(offset)
	for i := 0; i < len(d); i++ {
		h ^= uint64(d[i])
		h *= prime
	}
	return h
}

// Lookup checks name and each of its parent domains. It returns the list name
// and the matching suffix.
func (s *Snapshot) Lookup(name string) (list, matched string, ok bool) {
	if s == nil || len(s.hashes) == 0 {
		return "", "", false
	}
	for d := name; d != ""; d = domain.Parent(d) {
		h := Hash(d)
		i := sort.Search(len(s.hashes), func(i int) bool { return s.hashes[i] >= h })
		if i < len(s.hashes) && s.hashes[i] == h {
			return s.Lists[s.src[i]], d, true
		}
	}
	return "", "", false
}

// Builder collects domains from several lists and produces a Snapshot.
// It keys on hashes, not strings, so compiling 2M domains needs tens of MB
// rather than hundreds. Parent-covered entries are removed by a second
// streaming pass: call Prune for every domain after all Adds.
type Builder struct {
	lists []string
	m     map[uint64]uint16
}

func NewBuilder() *Builder { return &Builder{m: make(map[uint64]uint16)} }

// AddList registers a list name and returns its id for Add.
func (b *Builder) AddList(name string) uint16 {
	b.lists = append(b.lists, name)
	return uint16(len(b.lists) - 1)
}

// Add records d from list id. The first list that adds a domain owns it.
func (b *Builder) Add(id uint16, d string) {
	h := Hash(d)
	if _, ok := b.m[h]; !ok {
		b.m[h] = id
	}
}

// Prune drops d if one of its parent domains is also present, since the
// parent already blocks it.
func (b *Builder) Prune(d string) {
	for p := domain.Parent(d); p != ""; p = domain.Parent(p) {
		if _, ok := b.m[Hash(p)]; ok {
			delete(b.m, Hash(d))
			return
		}
	}
}

// Build returns the snapshot. The builder must not be used afterwards.
func (b *Builder) Build() *Snapshot {
	s := &Snapshot{Lists: slices.Clone(b.lists)}
	s.hashes = make([]uint64, 0, len(b.m))
	for h := range b.m {
		s.hashes = append(s.hashes, h)
	}
	slices.Sort(s.hashes)
	s.src = make([]uint16, len(s.hashes))
	for i, h := range s.hashes {
		s.src[i] = b.m[h]
	}
	b.m = nil
	return s
}

const magic = "ABWN"
const version = 1

// WriteFile writes the snapshot atomically (temp file + rename).
func (s *Snapshot) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	err = s.write(w)
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Snapshot) write(w io.Writer) error {
	le := binary.LittleEndian
	hdr := []byte(magic)
	hdr = le.AppendUint32(hdr, version)
	hdr = le.AppendUint32(hdr, uint32(len(s.Lists)))
	for _, n := range s.Lists {
		hdr = le.AppendUint16(hdr, uint16(len(n)))
		hdr = append(hdr, n...)
	}
	hdr = le.AppendUint32(hdr, uint32(len(s.hashes)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if err := binary.Write(w, le, s.hashes); err != nil {
		return err
	}
	return binary.Write(w, le, s.src)
}

// ReadFile loads a snapshot written by WriteFile.
func ReadFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return read(bufio.NewReader(f))
}

var errCorrupt = errors.New("lists.bin is corrupt")

func read(r io.Reader) (*Snapshot, error) {
	le := binary.LittleEndian
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, errCorrupt
	}
	if string(hdr[:4]) != magic {
		return nil, errCorrupt
	}
	if v := le.Uint32(hdr[4:]); v != version {
		return nil, fmt.Errorf("lists.bin version %d not supported", v)
	}
	n := le.Uint32(hdr[8:])
	if n > 1024 {
		return nil, errCorrupt
	}
	s := &Snapshot{}
	for i := uint32(0); i < n; i++ {
		var l uint16
		if err := binary.Read(r, le, &l); err != nil {
			return nil, errCorrupt
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, errCorrupt
		}
		s.Lists = append(s.Lists, string(name))
	}
	var count uint32
	if err := binary.Read(r, le, &count); err != nil || count > 50_000_000 {
		return nil, errCorrupt
	}
	s.hashes = make([]uint64, count)
	s.src = make([]uint16, count)
	if err := binary.Read(r, le, s.hashes); err != nil {
		return nil, errCorrupt
	}
	if err := binary.Read(r, le, s.src); err != nil {
		return nil, errCorrupt
	}
	for i := range s.src {
		if int(s.src[i]) >= len(s.Lists) || (i > 0 && s.hashes[i] <= s.hashes[i-1]) {
			return nil, errCorrupt
		}
	}
	return s, nil
}
