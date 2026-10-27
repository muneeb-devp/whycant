package checks

import (
	"strings"
	"syscall"
	"testing"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/core"
	"github.com/muneeb-devp/whycant/internal/mount"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func mkACL(entries ...acl.Entry) *acl.ACL { return &acl.ACL{Entries: entries} }

func e(tag uint16, perm uint16, id uint32) acl.Entry { return acl.Entry{Tag: tag, Perm: perm, ID: id} }

func TestDACWithACL(t *testing.T) {
	file := sys.TypeRegular
	tests := []struct {
		name     string
		subject  *core.Subject
		need     core.Perm
		acl      *acl.ACL
		severity core.Severity
		summary  string
		has      []string
	}{
		{
			// Scenario 5.
			name: "named user granted", subject: wwwData, need: core.PermR,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagUser, 4, 33), e(acl.TagGroupObj, 0, 0), e(acl.TagMask, 4, 0), e(acl.TagOther, 0, 0)),
			severity: core.Pass, summary: "ACL entry user:www-data gives r--, which includes r",
		},
		{
			// Scenario 6.
			name: "mask restricts named user", subject: wwwData, need: core.PermW,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagUser, 6, 33), e(acl.TagGroupObj, 4, 0), e(acl.TagMask, 4, 0), e(acl.TagOther, 0, 0)),
			severity: core.Blocker, summary: "the ACL mask removes write permission",
			has: []string{"The ACL entry user:www-data grants rw-, but the ACL mask is r--", "setfacl -m m::rw /srv/x"},
		},
		{
			name: "named user lacks bit", subject: wwwData, need: core.PermW,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagUser, 4, 33), e(acl.TagGroupObj, 4, 0), e(acl.TagMask, 6, 0), e(acl.TagOther, 6, 0)),
			severity: core.Blocker, summary: "named user class has no write permission",
			has: []string{"gives www-data only r--", "setfacl -m u:www-data:rw /srv/x"},
		},
		{
			name: "named group grants despite owning group", subject: alice, need: core.PermW,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagGroupObj, 4, 0), e(acl.TagGroup, 6, 1001), e(acl.TagMask, 6, 0), e(acl.TagOther, 0, 0)),
			severity: core.Pass, summary: "ACL entry group:deploy gives rw-, which includes w",
		},
		{
			name: "matching groups but none grants", subject: alice, need: core.PermW,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagGroupObj, 4, 0), e(acl.TagGroup, 4, 1001), e(acl.TagMask, 6, 0), e(acl.TagOther, 6, 0)),
			severity: core.Blocker, has: []string{"(group:: r--, group:deploy r--)"},
		},
		{
			name: "owner ignores mask", subject: alice, need: core.PermW,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagUser, 6, 33), e(acl.TagGroupObj, 0, 0), e(acl.TagMask, 0, 0), e(acl.TagOther, 0, 0)),
			severity: core.Pass,
		},
		{
			name: "other with ACL", subject: wwwData, need: core.PermR,
			acl:      mkACL(e(acl.TagUserObj, 6, 0), e(acl.TagUser, 6, 99), e(acl.TagGroupObj, 4, 0), e(acl.TagMask, 6, 0), e(acl.TagOther, 0, 0)),
			severity: core.Blocker, has: []string{"has no entry for www-data"},
		},
	}
	names := map[uint32]string{33: "www-data", 1000: "alice", 1001: "deploy"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner := uint32(1000)
			if tt.subject == alice {
				owner = 0
			}
			if tt.name == "owner ignores mask" {
				owner = 1000
			}
			n := node(core.RoleTarget, tt.need, file|0o640, owner, 1000)
			n.ACL = tt.acl
			action := core.Read
			if tt.need == core.PermW {
				action = core.Write
			}
			ctx := &Context{Subject: tt.subject, Action: action, InvokerUID: 1000, Names: fakeNames(names)}
			f := worst(DAC{}.Evaluate(ctx, n))
			if f.Severity != tt.severity {
				t.Fatalf("severity = %v, want %v: %+v", f.Severity, tt.severity, f)
			}
			if tt.summary != "" && f.Summary != tt.summary {
				t.Errorf("summary = %q, want %q", f.Summary, tt.summary)
			}
			all := f.Detail + "\n" + commands(f)
			for _, h := range tt.has {
				if !strings.Contains(all, h) {
					t.Errorf("finding %q missing %q", all, h)
				}
			}
		})
	}
}

type fakeNames map[uint32]string

func (f fakeNames) UserName(id uint32) string  { return f[id] }
func (f fakeNames) GroupName(id uint32) string { return f[id] }

func TestMountCheck(t *testing.T) {
	ro := &mount.Mount{MountPoint: "/data", FSType: "ext4", Options: []string{"ro"}, SuperOptions: []string{"rw"}}
	noexec := &mount.Mount{MountPoint: "/tmp", FSType: "tmpfs", Options: []string{"rw", "noexec", "nosuid"}}
	vfat := &mount.Mount{MountPoint: "/media/usb", FSType: "vfat", Options: []string{"rw"}, SuperOptions: []string{"rw", "uid=1000", "gid=1000"}}
	fuse := &mount.Mount{MountPoint: "/srv/x", FSType: "fuse.sshfs", Options: []string{"rw"}, SuperOptions: []string{"rw", "user_id=1000", "group_id=1000"}}
	nfs := &mount.Mount{MountPoint: "/", FSType: "nfs4", Options: []string{"rw"}}

	tests := []struct {
		name    string
		subject *core.Subject
		action  core.Action
		role    core.Role
		mode    uint32
		mount   *mount.Mount
		want    core.Severity
		has     string
	}{
		{"ro blocks write even for root", root, core.Write, core.RoleTarget, sys.TypeRegular | 0o644, ro, core.Blocker, "remount,rw,bind"},
		{"ro blocks create via parent", alice, core.Create, core.RoleParent, sys.TypeDir | 0o777, ro, core.Blocker, "read-only"},
		{"ro allows read", alice, core.Read, core.RoleTarget, sys.TypeRegular | 0o644, ro, core.Pass, ""},
		{"noexec blocks exec", root, core.Exec, core.RoleTarget, sys.TypeRegular | 0o755, noexec, core.Blocker, "sh /srv/x"},
		{"nosuid notes setuid", alice, core.Exec, core.RoleTarget, sys.TypeRegular | sys.ModeSetuid | 0o755, &mount.Mount{MountPoint: "/", FSType: "ext4", Options: []string{"nosuid"}}, core.Info, "setuid"},
		{"vfat warns", alice, core.Write, core.RoleTarget, sys.TypeRegular | 0o755, vfat, core.Warn, "uid=1000"},
		{"fuse without allow_other", wwwData, core.Traverse, core.RoleAncestor, sys.TypeDir | 0o755, fuse, core.Blocker, "allow_other"},
		{"fuse owner is fine", alice, core.Traverse, core.RoleAncestor, sys.TypeDir | 0o755, fuse, core.Pass, ""},
		{"nfs root squash", root, core.Read, core.RoleTarget, sys.TypeRegular | 0o644, nfs, core.Warn, "root_squash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node(tt.role, core.PermR, tt.mode, 0, 0)
			n.Mount = tt.mount
			ctx := &Context{Subject: tt.subject, Action: tt.action, InvokerUID: 1000, Names: fakeNames{1000: "alice"}}
			if !(Mount{}).Applies(ctx, n) {
				t.Fatal("does not apply")
			}
			fs := Mount{}.Evaluate(ctx, n)
			got := core.Pass
			if len(fs) > 0 {
				got = worst(fs).Severity
			}
			if got != tt.want {
				t.Fatalf("severity = %v, want %v: %+v", got, tt.want, fs)
			}
			if tt.has != "" {
				f := worst(fs)
				if all := f.Detail + commands(f) + f.Summary; !strings.Contains(all, tt.has) {
					t.Errorf("%q missing %q", all, tt.has)
				}
			}
		})
	}
}

func TestAttrs(t *testing.T) {
	tests := []struct {
		name   string
		action core.Action
		role   core.Role
		mode   uint32
		flags  uint32
		want   core.Severity
	}{
		{"immutable blocks write", core.Write, core.RoleTarget, sys.TypeRegular, sys.FlagImmutable, core.Blocker},
		{"immutable blocks delete", core.Delete, core.RoleTarget, sys.TypeRegular, sys.FlagImmutable, core.Blocker},
		{"append-only blocks write", core.Write, core.RoleTarget, sys.TypeRegular, sys.FlagAppendOnly, core.Blocker},
		{"append-only allows append", core.Append, core.RoleTarget, sys.TypeRegular, sys.FlagAppendOnly, core.Pass},
		{"immutable dir blocks create", core.Create, core.RoleParent, sys.TypeDir, sys.FlagImmutable, core.Blocker},
		{"append-only dir allows create", core.Create, core.RoleParent, sys.TypeDir, sys.FlagAppendOnly, core.Pass},
		{"append-only dir blocks delete", core.Delete, core.RoleParent, sys.TypeDir, sys.FlagAppendOnly, core.Blocker},
		{"plain", core.Write, core.RoleTarget, sys.TypeRegular, 0, core.Pass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := node(tt.role, 0, tt.mode|0o644, 0, 0)
			n.Flags, n.FlagsKnown = tt.flags, true
			ctx := &Context{Subject: root, Action: tt.action}
			if !(Attrs{}).Applies(ctx, n) {
				t.Fatal("does not apply")
			}
			if got := worst(Attrs{}.Evaluate(ctx, n)).Severity; got != tt.want {
				t.Errorf("severity = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSticky(t *testing.T) {
	dir := node(core.RoleParent, core.PermW|core.PermX, sys.TypeDir|sys.ModeSticky|0o777, 0, 0)
	dir.OwnerName = "root"
	file := node(core.RoleTarget, 0, sys.TypeRegular|0o644, 1000, 1000)
	file.Dir = dir

	tests := []struct {
		subject *core.Subject
		want    core.Severity
	}{
		{wwwData, core.Blocker}, // scenario 11
		{alice, core.Pass},      // owns the file
		{root, core.Pass},       // CAP_FOWNER
	}
	for _, tt := range tests {
		ctx := &Context{Subject: tt.subject, Action: core.Delete, InvokerUID: 33}
		if !(Sticky{}).Applies(ctx, file) {
			t.Fatal("does not apply")
		}
		if got := worst(Sticky{}.Evaluate(ctx, file)).Severity; got != tt.want {
			t.Errorf("%s: severity = %v, want %v", tt.subject.Name, got, tt.want)
		}
	}
}

func TestProtectedSymlinks(t *testing.T) {
	f := sys.NewFake()
	f.File("/proc/sys/fs/protected_symlinks", 0o444, 0, 0, "1\n")
	f.File("/proc/sys/fs/protected_regular", 0o444, 0, 0, "2\n")

	tmp := node(core.RoleAncestor, core.PermX, sys.TypeDir|sys.ModeSticky|0o777, 0, 0)
	link := node(core.RoleSymlink, 0, sys.TypeSymlink|0o777, 1000, 1000)
	link.Dir, link.Resolved = tmp, "/etc/passwd"

	for _, tt := range []struct {
		subject *core.Subject
		want    int
	}{{wwwData, 1}, {root, 1}, {alice, 0}} { // scenario 18; root is not exempt
		ctx := &Context{Sys: f, Subject: tt.subject, Action: core.Read, InvokerUID: 0}
		if got := len(Protected{}.Evaluate(ctx, link)); got != tt.want {
			t.Errorf("%s: %d findings, want %d", tt.subject.Name, got, tt.want)
		}
	}

	off := sys.NewFake()
	off.File("/proc/sys/fs/protected_symlinks", 0o444, 0, 0, "0\n")
	if fs := (Protected{}).Evaluate(&Context{Sys: off, Subject: wwwData}, link); len(fs) != 0 {
		t.Errorf("sysctl off: %+v", fs)
	}

	// protected_regular=2 also covers group-writable sticky directories.
	shared := node(core.RoleParent, core.PermW|core.PermX, sys.TypeDir|sys.ModeSticky|0o770, 0, 0)
	existing := node(core.RoleTarget, 0, sys.TypeRegular|0o666, 1000, 1000)
	existing.Dir = shared
	ctx := &Context{Sys: f, Subject: wwwData, Action: core.Create}
	if !(Protected{}).Applies(ctx, existing) || len(Protected{}.Evaluate(ctx, existing)) != 1 {
		t.Error("protected_regular=2 not enforced")
	}
}

func TestSuggest(t *testing.T) {
	f := sys.NewFake()
	f.File("/etc/nginx/nginx.conf", 0o644, 0, 0, "")
	f.File("/etc/nginx/mime.types", 0o644, 0, 0, "")
	dir := &core.Node{Path: "/etc/nginx"}
	ctx := &Context{Sys: f}
	for missing, want := range map[string]string{
		"/etc/nginx/ngnix.conf": "/etc/nginx/nginx.conf",
		"/etc/nginx/NGINX.CONF": "/etc/nginx/nginx.conf",
		"/etc/nginx/zzz":        "",
	} {
		got := suggest(ctx, &core.Node{Path: missing, Dir: dir})
		if got != want {
			t.Errorf("suggest(%q) = %q, want %q", missing, got, want)
		}
	}
}

func TestLSMDetectionFallback(t *testing.T) {
	f := sys.NewFake() // no securityfs
	f.File("/sys/fs/selinux/enforce", 0o444, 0, 0, "0\n")
	f.File("/sys/module/apparmor/parameters/enabled", 0o444, 0, 0, "Y\n")
	st := (&Context{Sys: f}).lsm()
	if !st.selinux || !st.apparmor || st.enforce != 0 {
		t.Errorf("lsm = %+v", st)
	}

	g := sys.NewFake()
	g.File("/sys/kernel/security/lsm", 0o444, 0, 0, "selinux\n")
	g.SetCommand("Enforcing\n", nil, "getenforce")
	if st := (&Context{Sys: g}).lsm(); st.enforce != 1 {
		t.Errorf("getenforce fallback: %+v", st)
	}

	none := sys.NewFake()
	if st := (&Context{Sys: none}).lsm(); st.selinux || st.apparmor {
		t.Errorf("no LSM: %+v", st)
	}
}

func TestSEType(t *testing.T) {
	if seType("system_u:object_r:httpd_sys_content_t:s0") != "httpd_sys_content_t" || seType("weird") != "weird" {
		t.Error("seType")
	}
	if !hasToken("a ino=42 b", "ino=42") || hasToken("a ino=421 b", "ino=42") {
		t.Error("hasToken")
	}
	if field(`x profile="/usr/sbin/mysqld" y`, "profile") != "/usr/sbin/mysqld" {
		t.Error("field")
	}
}

func TestAttrsUnreadable(t *testing.T) {
	n := node(core.RoleTarget, core.PermW, sys.TypeRegular|0o666, 0, 0)
	n.FlagsErr = syscall.EACCES
	ctx := &Context{Subject: alice, Action: core.Write, InvokerName: "alice"}
	if f := worst(Attrs{}.Evaluate(ctx, n)); f.Severity != core.Info || !strings.Contains(f.Detail, "sudo") {
		t.Errorf("unreadable attrs = %+v", f)
	}
	n.FlagsErr = sys.ErrNotSupported
	if f := worst(Attrs{}.Evaluate(ctx, n)); f.Severity != core.Pass {
		t.Errorf("unsupported attrs = %+v", f)
	}
}
