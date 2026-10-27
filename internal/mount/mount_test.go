package mount

import (
	"testing"
)

const sample = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
40 22 8:2 / /mnt/my\040disk rw,nosuid master:3 propagate_from:2 - vfat /dev/sdb1 rw,uid=1000,gid=1000,fmask=0022,dmask=0022
41 22 8:1 /srv/data /srv/ro ro,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
42 22 0:50 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=100k
43 42 0:51 / /tmp rw,noexec - tmpfs tmpfs rw
44 22 0:52 / /home/alice/remote rw,nosuid,nodev,relatime - fuse.sshfs alice@host: rw,user_id=1000,group_id=1000
`

func TestParse(t *testing.T) {
	tab, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(tab) != 7 {
		t.Fatalf("got %d mounts", len(tab))
	}
	m := tab[2]
	if m.MountPoint != "/mnt/my disk" || m.FSType != "vfat" || m.Source != "/dev/sdb1" {
		t.Errorf("vfat mount = %+v", m)
	}
	if v, ok := m.Value("uid"); !ok || v != "1000" {
		t.Errorf("uid option = %q, %v", v, ok)
	}
	if !m.Has("nosuid") || m.Has("noexec") {
		t.Error("options wrong")
	}
	if !tab[3].ReadOnly() || tab[3].Root != "/srv/data" {
		t.Errorf("bind mount = %+v", tab[3])
	}
	if tab[0].ReadOnly() {
		t.Error("errors=remount-ro must not count as ro")
	}
}

func TestLookup(t *testing.T) {
	tab, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]int{
		"/":                     22,
		"/etc/passwd":           22,
		"/proc/self":            23,
		"/procfs":               22,
		"/mnt/my disk/x":        40,
		"/srv/ro":               41,
		"/srv/ro/file":          41,
		"/tmp/x":                43, // the later mount stacks on top
		"/home/alice/remote/a":  44,
		"/home/alice/remotefoo": 22,
	}
	for p, want := range tests {
		if got := tab.Lookup(p); got == nil || got.ID != want {
			t.Errorf("Lookup(%q) = %+v, want id %d", p, got, want)
		}
	}
}

func TestUnescape(t *testing.T) {
	tests := map[string]string{
		`plain`:         "plain",
		`a\040b`:        "a b",
		`tab\011x`:      "tab\tx",
		`nl\012`:        "nl\n",
		`back\134slash`: `back\slash`,
		`bad\09`:        `bad\09`,
		`end\04`:        `end\04`,
		`\`:             `\`,
	}
	for in, want := range tests {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMalformed(t *testing.T) {
	for _, bad := range []string{
		"22 1 8:1 / / rw\n",
		"x 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
		"22 1 81 / / rw - ext4 /dev/sda1 rw\n",
		"22 1 8:1 / / rw shared:1 -\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func FuzzParseMountinfo(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("1 2 3:4 / / rw - x y\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tab, err := Parse(data)
		if err != nil {
			return
		}
		for _, m := range tab {
			_ = tab.Lookup(m.MountPoint)
			_ = m.ReadOnly()
		}
	})
}
