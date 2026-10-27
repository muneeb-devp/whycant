// Package mount parses /proc/self/mountinfo and finds the mount that holds
// a path.
package mount

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Mount is one line of mountinfo.
type Mount struct {
	ID         int
	ParentID   int
	Major      int
	Minor      int
	Root       string // path within the filesystem that is mounted here
	MountPoint string
	Options    []string // per-mount options (ro, noexec, nosuid, ...)
	FSType     string
	Source     string
	// SuperOptions are filesystem-wide options (uid=, umask=, allow_other...).
	SuperOptions []string
}

// Has reports whether a per-mount or superblock option is set exactly.
func (m *Mount) Has(opt string) bool {
	for _, o := range m.Options {
		if o == opt {
			return true
		}
	}
	for _, o := range m.SuperOptions {
		if o == opt {
			return true
		}
	}
	return false
}

// Value returns the value of a key=value option, preferring superblock options.
func (m *Mount) Value(key string) (string, bool) {
	for _, opts := range [][]string{m.SuperOptions, m.Options} {
		for _, o := range opts {
			if k, v, ok := strings.Cut(o, "="); ok && k == key {
				return v, true
			}
		}
	}
	return "", false
}

// ReadOnly reports whether the mount or its filesystem is read-only.
func (m *Mount) ReadOnly() bool { return m.Has("ro") }

// Table is the parsed mount table in mountinfo order.
type Table []Mount

// Parse decodes mountinfo:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//
// Optional fields (zero or more) end at the "-" separator.
func Parse(data []byte) (Table, error) {
	var t Table
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		m, err := parseLine(text)
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", line, err)
		}
		t = append(t, m)
	}
	return t, sc.Err()
}

func parseLine(text string) (Mount, error) {
	f := strings.Fields(text)
	sep := -1
	for i := 6; i < len(f); i++ {
		if f[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || len(f) < sep+3 {
		return Mount{}, fmt.Errorf("malformed line %q", text)
	}
	id, err1 := strconv.Atoi(f[0])
	parent, err2 := strconv.Atoi(f[1])
	majS, minS, ok := strings.Cut(f[2], ":")
	maj, err3 := strconv.Atoi(majS)
	minor, err4 := strconv.Atoi(minS)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || !ok {
		return Mount{}, fmt.Errorf("malformed ids in %q", text)
	}
	m := Mount{
		ID: id, ParentID: parent, Major: maj, Minor: minor,
		Root:       unescape(f[3]),
		MountPoint: unescape(f[4]),
		Options:    strings.Split(f[5], ","),
		FSType:     unescape(f[sep+1]),
		Source:     unescape(f[sep+2]),
	}
	if len(f) > sep+3 {
		m.SuperOptions = strings.Split(f[sep+3], ",")
	}
	return m, nil
}

// unescape decodes the kernel's octal escapes (\040 for space, \011 tab,
// \012 newline, \134 backslash).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) && isOctal(s[i+1:i+4]) {
			n, _ := strconv.ParseUint(s[i+1:i+4], 8, 8)
			b.WriteByte(byte(n))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '7' {
			return false
		}
	}
	return s[0] <= '3' // fits in a byte
}

// Lookup returns the mount holding path: the longest matching mount point,
// and among equal ones the last listed, since later mounts stack on top.
func (t Table) Lookup(path string) *Mount {
	var best *Mount
	for i := range t {
		m := &t[i]
		if !under(path, m.MountPoint) {
			continue
		}
		if best == nil || len(m.MountPoint) >= len(best.MountPoint) {
			best = m
		}
	}
	return best
}

func under(path, mp string) bool {
	if mp == "/" || path == mp {
		return true
	}
	return strings.HasPrefix(path, mp+"/")
}
