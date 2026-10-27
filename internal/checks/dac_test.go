package checks

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/sys"
)

var (
	alice   = &core.Subject{Name: "alice", UID: 1000, GID: 1000, Groups: []uint32{1000, 1001}}
	wwwData = &core.Subject{Name: "www-data", UID: 33, GID: 33, Groups: []uint32{33}}
	root    = &core.Subject{Name: "root", UID: 0, GID: 0, Groups: []uint32{0}, Caps: core.AllCaps}
	reader  = &core.Subject{Name: "backup", UID: 34, GID: 34, Groups: []uint32{34}, Caps: 1 << core.CapDACReadSearch}
)

func node(role core.Role, need core.Perm, mode, uid, gid uint32) *core.Node {
	return &core.Node{
		Path: "/srv/x", Resolved: "/srv/x", Role: role, Need: need, Exists: true,
		Info:      sys.FileInfo{Mode: mode, UID: uid, GID: gid},
		OwnerName: map[uint32]string{0: "root", 33: "www-data", 1000: "alice", 1001: "deploy"}[uid],
		GroupName: map[uint32]string{0: "root", 33: "www-data", 1000: "alice", 1001: "deploy"}[gid],
	}
}

func TestDAC(t *testing.T) {
	const (
		dir  = sys.TypeDir
		file = sys.TypeRegular
	)
	tests := []struct {
		name      string
		subject   *core.Subject
		action    core.Action
		node      *core.Node
		severity  core.Severity
		summary   string
		detailHas []string
		fixesHave []string
		fixesLack []string
	}{
		{
			name: "scenario 1: other lacks x on ancestor", subject: wwwData, action: core.Read,
			node:     node(core.RoleAncestor, core.PermX, dir|0o750, 1001, 1001),
			severity: core.Blocker, summary: "other class has no execute permission",
			detailHas: []string{`www-data is not the owner (deploy) and is not in group "deploy",` + "\n" + `so the "other" permissions apply: ---. Entering a directory needs x.`},
			fixesHave: []string{"sudo setfacl -m u:www-data:x /srv/x", "sudo usermod -aG deploy www-data"},
		},
		{
			name: "group fix only when the group has the bit", subject: wwwData, action: core.Read,
			node:      node(core.RoleTarget, core.PermR, file|0o600, 1001, 1001),
			severity:  core.Blocker,
			fixesHave: []string{"sudo setfacl -m u:www-data:r /srv/x"},
			fixesLack: []string{"usermod"},
		},
		{
			name: "scenario 2: owner precedence", subject: alice, action: core.Read,
			node:     node(core.RoleTarget, core.PermR, file|0o047, 1000, 1000),
			severity: core.Blocker, summary: "owner class has no read permission",
			detailHas: []string{"alice owns /srv/x, so only the owner permissions apply: ---.", "never\napply to the owner"},
			fixesHave: []string{"chmod u+r /srv/x"},
			fixesLack: []string{"sudo", "setfacl"},
		},
		{
			name: "group precedence over other", subject: alice, action: core.Write,
			node:     node(core.RoleTarget, core.PermW, file|0o646, 0, 1001),
			severity: core.Blocker, summary: "group class has no write permission",
			detailHas: []string{`but is in group "deploy"`, "never apply to members\nof the file's group"},
			fixesHave: []string{"sudo setfacl -m u:alice:rw /srv/x", "sudo chmod g+w /srv/x"},
		},
		{
			name: "scenario 3: group grants", subject: alice, action: core.Read,
			node:     node(core.RoleTarget, core.PermR, file|0o640, 0, 1001),
			severity: core.Pass, summary: "group permissions r-- include r",
		},
		{
			name: "owner grants", subject: alice, action: core.Exec,
			node:     node(core.RoleTarget, core.PermX, file|0o700, 1000, 1000),
			severity: core.Pass,
		},
		{
			name: "scenario 19: root reads a 000 file", subject: root, action: core.Read,
			node:     node(core.RoleTarget, core.PermR, file, 1000, 1000),
			severity: core.Pass, summary: "root bypasses the permission bits",
		},
		{
			name: "root traverses a 000 dir", subject: root, action: core.Traverse,
			node:     node(core.RoleAncestor, core.PermX, dir, 1000, 1000),
			severity: core.Pass,
		},
		{
			name: "scenario 19: root cannot exec without any x bit", subject: root, action: core.Exec,
			node:     node(core.RoleTarget, core.PermX, file|0o644, 1000, 1000),
			severity: core.Blocker, summary: "no execute bit is set",
			detailHas: []string{"at least one execute bit", "-rw-r--r--"},
			fixesHave: []string{"chmod u+x /srv/x"},
		},
		{
			name: "root execs with only other x", subject: root, action: core.Exec,
			node:     node(core.RoleTarget, core.PermX, file|0o001, 1000, 1000),
			severity: core.Pass,
		},
		{
			name: "dac_read_search reads but cannot write", subject: reader, action: core.Write,
			node:     node(core.RoleTarget, core.PermW, file|0o600, 1000, 1000),
			severity: core.Blocker,
		},
		{
			name: "dac_read_search reads", subject: reader, action: core.Read,
			node:     node(core.RoleTarget, core.PermR, file, 1000, 1000),
			severity: core.Pass,
		},
		{
			name: "list with r but no x warns", subject: wwwData, action: core.List,
			node:     node(core.RoleTarget, core.PermR, dir|0o754, 1000, 1000),
			severity: core.Warn, summary: "can list names but not open or inspect entries",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{Subject: tt.subject, Action: tt.action, InvokerUID: 1000, InvokerName: "alice"}
			if !(DAC{}).Applies(ctx, tt.node) {
				t.Fatal("DAC does not apply")
			}
			findings := DAC{}.Evaluate(ctx, tt.node)
			f := worst(findings)
			if f.Severity != tt.severity {
				t.Fatalf("severity = %v, want %v (%+v)", f.Severity, tt.severity, f)
			}
			if tt.summary != "" && f.Summary != tt.summary {
				t.Errorf("summary = %q, want %q", f.Summary, tt.summary)
			}
			for _, s := range tt.detailHas {
				if !strings.Contains(f.Detail, s) {
					t.Errorf("detail %q missing %q", f.Detail, s)
				}
			}
			cmds := commands(f)
			for _, s := range tt.fixesHave {
				if !strings.Contains(cmds, s) {
					t.Errorf("fixes %q missing %q", cmds, s)
				}
			}
			for _, s := range tt.fixesLack {
				if strings.Contains(cmds, s) {
					t.Errorf("fixes %q should not contain %q", cmds, s)
				}
			}
		})
	}
}

func TestDACCurrentUserNote(t *testing.T) {
	s := *wwwData
	s.Current = true
	ctx := &Context{Subject: &s, Action: core.Read, InvokerUID: 33}
	f := DAC{}.Evaluate(ctx, node(core.RoleAncestor, core.PermX, sys.TypeDir|0o750, 1001, 1001))[0]
	if f.Fixes[1].Note != "log out and back in afterwards" {
		t.Errorf("note = %q", f.Fixes[1].Note)
	}
}

func TestPathCheck(t *testing.T) {
	ctx := &Context{Subject: alice, Action: core.Read, InvokerName: "alice", Argv: []string{"whycant", "read", "/root/my file"}}
	tests := []struct {
		name     string
		action   core.Action
		node     *core.Node
		severity core.Severity
		cmd      string
	}{
		{"missing", core.Read, &core.Node{Path: "/x", Role: core.RoleTarget, Err: syscall.ENOENT}, core.Blocker, ""},
		{"eacces", core.Read, &core.Node{Path: "/root/a", Role: core.RoleAncestor, Err: syscall.EACCES}, core.Unknown, "sudo whycant read '/root/my file'"},
		{"other error", core.Read, &core.Node{Path: "/x", Role: core.RoleTarget, Err: errors.New("io")}, core.Unknown, ""},
		{"file as ancestor", core.Read, node(core.RoleAncestor, core.PermX, sys.TypeRegular|0o644, 0, 0), core.Blocker, ""},
		{"symlink", core.Read, node(core.RoleSymlink, 0, sys.TypeSymlink|0o777, 0, 0), core.Pass, ""},
		{"loop", core.Read, &core.Node{Path: "/l", Role: core.RoleSymlink, Err: syscall.ELOOP}, core.Blocker, ""},
		{"create new", core.Create, &core.Node{Path: "/x", Role: core.RoleTarget, Err: syscall.ENOENT}, core.Pass, ""},
		{"traverse a file", core.Traverse, node(core.RoleTarget, core.PermX, sys.TypeRegular|0o755, 0, 0), core.Blocker, ""},
		{"write a dir", core.Write, node(core.RoleTarget, core.PermW, sys.TypeDir|0o777, 0, 0), core.Blocker, ""},
		{"exec a fifo", core.Exec, node(core.RoleTarget, core.PermX, sys.TypeFIFO|0o777, 0, 0), core.Blocker, ""},
		{"read a dir", core.Read, node(core.RoleTarget, core.PermR, sys.TypeDir|0o755, 0, 0), core.Info, "whycant list /srv/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx.Action = tt.action
			f := worst(Path{}.Evaluate(ctx, tt.node))
			if f.Severity != tt.severity {
				t.Fatalf("severity = %v, want %v (%+v)", f.Severity, tt.severity, f)
			}
			if !strings.Contains(commands(f)+f.Detail, tt.cmd) {
				t.Errorf("finding %+v missing %q", f, tt.cmd)
			}
			if (DAC{}).Applies(ctx, tt.node) && tt.severity >= core.Unknown {
				t.Error("DAC applies to a node the path check rejected")
			}
		})
	}
}

func worst(fs []core.Finding) core.Finding {
	var w core.Finding
	for i, f := range fs {
		if i == 0 || f.Severity > w.Severity {
			w = f
		}
	}
	return w
}

func commands(f core.Finding) string {
	var all []string
	for _, fx := range f.Fixes {
		all = append(all, fx.Commands...)
	}
	return strings.Join(all, "\n")
}
