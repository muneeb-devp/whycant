package walk

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

type want struct {
	path   string
	role   core.Role
	need   core.Perm
	exists bool
}

func check(t *testing.T, nodes []*core.Node, wants []want) {
	t.Helper()
	if len(nodes) != len(wants) {
		t.Fatalf("got %d nodes, want %d", len(nodes), len(wants))
	}
	for i, w := range wants {
		n := nodes[i]
		if n.Path != w.path || n.Role != w.role || n.Need != w.need || n.Exists != w.exists {
			t.Errorf("node %d = {%s %v %v exists=%v}, want %+v", i, n.Path, n.Role, n.Need, n.Exists, w)
		}
	}
}

func TestWalk(t *testing.T) {
	f := sys.NewFake()
	f.File("/srv/app/db.yml", 0o640, 0, 0, "")

	nodes, err := Walk(f, core.Read, "/srv/app/db.yml")
	if err != nil {
		t.Fatal(err)
	}
	check(t, nodes, []want{
		{"/", core.RoleAncestor, core.PermX, true},
		{"/srv", core.RoleAncestor, core.PermX, true},
		{"/srv/app", core.RoleAncestor, core.PermX, true},
		{"/srv/app/db.yml", core.RoleTarget, core.PermR, true},
	})
}

func TestWalkRelativeAndRoot(t *testing.T) {
	f := sys.NewFake()
	f.Dir("/home/alice", 0o755, 1000, 1000)
	f.Cwd = "/home"

	nodes, err := Walk(f, core.List, "alice/./")
	if err != nil {
		t.Fatal(err)
	}
	if got := nodes[len(nodes)-1].Path; got != "/home/alice" {
		t.Errorf("target = %q", got)
	}

	nodes, err = Walk(f, core.Traverse, "/")
	if err != nil {
		t.Fatal(err)
	}
	check(t, nodes, []want{{"/", core.RoleTarget, core.PermX, true}})
}

func TestWalkStops(t *testing.T) {
	f := sys.NewFake()
	f.File("/etc/hosts", 0o644, 0, 0, "")
	f.Dir("/root", 0o700, 0, 0)
	f.Dir("/root/secret", 0o700, 0, 0).Err = syscall.EACCES

	// Missing component: later ones are not lstatted.
	nodes, _ := Walk(f, core.Read, "/srv/missing/file")
	if !errors.Is(nodes[1].Err, fs.ErrNotExist) || nodes[2].Exists || nodes[2].Err != nil {
		t.Errorf("missing walk = %+v %+v", nodes[1], nodes[2])
	}

	// A file used as a directory ends the walk.
	nodes, _ = Walk(f, core.Read, "/etc/hosts/x")
	if !nodes[2].Exists || nodes[3].Exists || nodes[3].Err != nil {
		t.Errorf("notdir walk = %+v %+v", nodes[2], nodes[3])
	}

	// whycant cannot inspect a component.
	nodes, _ = Walk(f, core.Read, "/root/secret/key")
	if !errors.Is(nodes[2].Err, fs.ErrPermission) || nodes[3].Exists {
		t.Errorf("eacces walk = %+v %+v", nodes[2], nodes[3])
	}
}

func TestTargetNeed(t *testing.T) {
	tests := map[core.Action]core.Perm{
		core.Read: core.PermR, core.List: core.PermR,
		core.Write: core.PermW, core.Append: core.PermW,
		core.Exec: core.PermX, core.Traverse: core.PermX,
	}
	for a, p := range tests {
		if got := TargetNeed(a); got != p {
			t.Errorf("TargetNeed(%v) = %v, want %v", a, got, p)
		}
	}
}

func paths(nodes []*core.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Path + ":" + n.Role.String()
	}
	return out
}

func TestWalkSymlinks(t *testing.T) {
	f := sys.NewFake()
	f.File("/usr/bin/ls", 0o755, 0, 0, "")
	f.Symlink("/bin", "usr/bin", 0, 0)
	f.Dir("/srv/releases/v2", 0o755, 0, 0)
	f.File("/srv/releases/v2/app.conf", 0o644, 0, 0, "")
	f.Symlink("/srv/current", "/srv/releases/v2", 0, 0)
	f.Symlink("/srv/up", "releases/../current", 0, 0)
	f.Symlink("/loop/a", "b", 0, 0)
	f.Symlink("/loop/b", "a", 0, 0)
	f.Symlink("/srv/dangling", "nowhere", 0, 0)

	tests := []struct {
		action core.Action
		path   string
		want   []string
	}{
		{core.Exec, "/bin/ls", []string{"/:ancestor", "/bin:symlink", "/usr:ancestor", "/usr/bin:ancestor", "/usr/bin/ls:target"}},
		{core.Read, "/srv/current/app.conf", []string{
			"/:ancestor", "/srv:ancestor", "/srv/current:symlink", "/srv/releases:ancestor",
			"/srv/releases/v2:ancestor", "/srv/releases/v2/app.conf:target",
		}},
		// ".." inside a link target and a link to a link.
		{core.Read, "/srv/up/app.conf", []string{
			"/:ancestor", "/srv:ancestor", "/srv/up:symlink", "/srv/releases:ancestor",
			"/srv/current:symlink", "/srv/releases/v2:ancestor", "/srv/releases/v2/app.conf:target",
		}},
		// A final symlink is followed for read but not for delete.
		{core.List, "/srv/current", []string{"/:ancestor", "/srv:ancestor", "/srv/current:symlink", "/srv/releases:ancestor", "/srv/releases/v2:target"}},
		{core.Delete, "/srv/current", []string{"/:ancestor", "/srv:parent", "/srv/current:target"}},
		{core.Create, "/srv/new.txt", []string{"/:ancestor", "/srv:parent", "/srv/new.txt:target"}},
		{core.Read, "/srv/dangling", []string{"/:ancestor", "/srv:ancestor", "/srv/dangling:symlink", "/srv/nowhere:target"}},
	}
	for _, tt := range tests {
		nodes, err := Walk(f, tt.action, tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := paths(nodes); !equal(got, tt.want) {
			t.Errorf("%v %s:\n got %v\nwant %v", tt.action, tt.path, got, tt.want)
		}
	}

	nodes, _ := Walk(f, core.Read, "/loop/a")
	last := nodes[len(nodes)-1]
	if !errors.Is(nodes[len(nodes)-1].Err, syscall.ELOOP) && !errors.Is(nodes[len(nodes)-2].Err, syscall.ELOOP) {
		t.Errorf("loop not detected: %v (last %+v)", paths(nodes), last)
	}
	if len(nodes) > 10 {
		t.Errorf("loop produced %d nodes", len(nodes))
	}

	nodes, _ = Walk(f, core.Read, "/srv/current")
	if n := nodes[2]; n.Resolved != "/srv/releases/v2" {
		t.Errorf("symlink Resolved = %q", n.Resolved)
	}
}

func TestWalkEnrich(t *testing.T) {
	f := sys.NewFake()
	f.File("/proc/self/mountinfo", 0o444, 0, 0,
		"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / /data ro - ext4 /dev/sdb1 rw\n")
	f.Dir("/data", 0o755, 0, 0)
	file := f.File("/data/f", 0o644, 0, 0, "")
	file.Flags = sys.FlagImmutable
	file.Xattrs = map[string][]byte{acl.XattrAccess: (&acl.ACL{Entries: []acl.Entry{
		{Tag: acl.TagUserObj, Perm: 6},
		{Tag: acl.TagUser, Perm: 6, ID: 33},
		{Tag: acl.TagGroupObj, Perm: 4},
		{Tag: acl.TagMask, Perm: 6},
		{Tag: acl.TagOther, Perm: 4},
	}}).Encode()}

	nodes, err := Walk(f, core.Write, "/data/f")
	if err != nil {
		t.Fatal(err)
	}
	n := nodes[2]
	if n.Mount == nil || n.Mount.MountPoint != "/data" || !n.Mount.ReadOnly() {
		t.Errorf("mount = %+v", n.Mount)
	}
	if n.ACL == nil || !n.FlagsKnown || n.Flags != sys.FlagImmutable {
		t.Errorf("node = %+v", n)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
