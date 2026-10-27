package walk

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"

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
