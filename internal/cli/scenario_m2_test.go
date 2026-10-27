package cli

import (
	"testing"

	"github.com/muneeb-devp/whycant/internal/acl"
	"github.com/muneeb-devp/whycant/internal/sys"
)

func withACL(n *sys.FakeFile, xattr string, entries ...acl.Entry) {
	if n.Xattrs == nil {
		n.Xattrs = map[string][]byte{}
	}
	n.Xattrs[xattr] = (&acl.ACL{Entries: entries}).Encode()
}

// TestChainScenarios covers the brief's milestone 2 scenarios against a fake.
// Each has a real-kernel counterpart in test/integration.
func TestChainScenarios(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *sys.Fake)
		args  []string
		code  int
	}{
		{
			// Scenario 5.
			name: "acl_named_user",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/app", 0o750, 1001, 1001)
				withACL(f.File("/srv/app/db.yml", 0o640, 1001, 1001, ""), acl.XattrAccess,
					acl.Entry{Tag: acl.TagUserObj, Perm: 6}, acl.Entry{Tag: acl.TagUser, Perm: 4, ID: 33},
					acl.Entry{Tag: acl.TagGroupObj, Perm: 4}, acl.Entry{Tag: acl.TagMask, Perm: 4}, acl.Entry{Tag: acl.TagOther})
				withACL(f.Files["/srv/app"], acl.XattrAccess,
					acl.Entry{Tag: acl.TagUserObj, Perm: 7}, acl.Entry{Tag: acl.TagUser, Perm: 1, ID: 33},
					acl.Entry{Tag: acl.TagGroupObj, Perm: 5}, acl.Entry{Tag: acl.TagMask, Perm: 5}, acl.Entry{Tag: acl.TagOther})
			},
			args: []string{"-u", "www-data", "read", "/srv/app/db.yml"},
			code: ExitAllowed,
		},
		{
			// Scenario 6.
			name: "acl_mask",
			setup: func(f *sys.Fake) {
				withACL(f.File("/srv/upload.log", 0o640, 1001, 1001, ""), acl.XattrAccess,
					acl.Entry{Tag: acl.TagUserObj, Perm: 6}, acl.Entry{Tag: acl.TagUser, Perm: 6, ID: 33},
					acl.Entry{Tag: acl.TagGroupObj, Perm: 4}, acl.Entry{Tag: acl.TagMask, Perm: 4}, acl.Entry{Tag: acl.TagOther})
			},
			args: []string{"-u", "www-data", "write", "/srv/upload.log"},
			code: ExitDenied,
		},
		{
			// Scenario 7.
			name: "ro_bind_mount",
			setup: func(f *sys.Fake) {
				f.File("/srv/data/report.csv", 0o666, 0, 0, "")
				addMount(f, "40 22 8:1 /var/data /srv/data ro,relatime shared:1 - ext4 /dev/sda1 rw")
			},
			args: []string{"-u", "alice", "write", "/srv/data/report.csv"},
			code: ExitDenied,
		},
		{
			// Scenario 8.
			name: "noexec_mount",
			setup: func(f *sys.Fake) {
				f.Dir("/tmp", 0o1777, 0, 0)
				f.File("/tmp/build.sh", 0o755, 1000, 1000, "#!/bin/sh\necho hi\n")
				addMount(f, "41 22 0:50 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw")
			},
			args: []string{"-u", "alice", "exec", "/tmp/build.sh"},
			code: ExitDenied,
		},
		{
			// Scenarios 9 and 19: immutable stops root.
			name: "immutable_root_write",
			setup: func(f *sys.Fake) {
				f.File("/etc/resolv.conf", 0o644, 0, 0, "").Flags = sys.FlagImmutable
			},
			args: []string{"-u", "root", "write", "/etc/resolv.conf"},
			code: ExitDenied,
		},
		{
			name: "immutable_delete",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/keep", 0o777, 0, 0)
				f.File("/srv/keep/pinned", 0o666, 1000, 1000, "").Flags = sys.FlagImmutable
			},
			args: []string{"-u", "alice", "delete", "/srv/keep/pinned"},
			code: ExitDenied,
		},
		{
			// Scenario 10.
			name: "append_only_write",
			setup: func(f *sys.Fake) {
				f.Dir("/var/log", 0o755, 0, 0)
				f.File("/var/log/audit.trail", 0o644, 0, 0, "").Flags = sys.FlagAppendOnly
			},
			args: []string{"-u", "root", "write", "/var/log/audit.trail"},
			code: ExitDenied,
		},
		{
			name: "append_only_append",
			setup: func(f *sys.Fake) {
				f.Dir("/var/log", 0o755, 0, 0)
				f.File("/var/log/audit.trail", 0o644, 0, 0, "").Flags = sys.FlagAppendOnly
			},
			args: []string{"-u", "root", "append", "/var/log/audit.trail"},
			code: ExitAllowed,
		},
		{
			// Scenario 11.
			name: "sticky_delete",
			setup: func(f *sys.Fake) {
				f.Dir("/tmp", 0o1777, 0, 0)
				f.File("/tmp/alice-session", 0o600, 1000, 1000, "")
			},
			args: []string{"-u", "www-data", "delete", "/tmp/alice-session"},
			code: ExitDenied,
		},
		{
			// Scenario 17: an intermediate link target blocks traversal.
			name: "symlink_chain_blocked",
			setup: func(f *sys.Fake) {
				f.Dir("/opt/releases", 0o700, 1001, 1001)
				f.File("/opt/releases/v2/static/index.html", 0o644, 1001, 1001, "")
				f.Symlink("/srv/current", "/opt/releases/v2", 0, 0)
			},
			args: []string{"-u", "www-data", "read", "/srv/current/static/index.html"},
			code: ExitDenied,
		},
		{
			// Scenario 18.
			name: "protected_symlinks",
			setup: func(f *sys.Fake) {
				f.File("/proc/sys/fs/protected_symlinks", 0o444, 0, 0, "1\n")
				f.Dir("/tmp", 0o1777, 0, 0)
				f.Symlink("/tmp/report.txt", "/home/alice/report.txt", 1000, 1000)
				f.File("/home/alice/report.txt", 0o644, 1000, 1000, "")
			},
			args: []string{"-u", "www-data", "read", "/tmp/report.txt"},
			code: ExitDenied,
		},
		{
			// Scenario 19: read-only mounts stop root too.
			name: "ro_root_create",
			setup: func(f *sys.Fake) {
				f.Dir("/boot/efi", 0o755, 0, 0)
				addMount(f, "45 22 8:3 / /boot/efi ro,relatime - vfat /dev/sda3 ro,fmask=0077,dmask=0077")
			},
			args: []string{"-u", "root", "create", "/boot/efi/grub.cfg"},
			code: ExitDenied,
		},
		{
			// Scenario 21.
			name: "create_w_without_x",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/inbox", 0o772, 1001, 1001)
			},
			args: []string{"-u", "www-data", "create", "/srv/inbox/upload.bin"},
			code: ExitDenied,
		},
		{
			name: "create_allowed_default_acl",
			setup: func(f *sys.Fake) {
				withACL(f.Dir("/srv/shared", 0o2775, 1001, 1001), acl.XattrDefault,
					acl.Entry{Tag: acl.TagUserObj, Perm: 7}, acl.Entry{Tag: acl.TagUser, Perm: 5, ID: 33},
					acl.Entry{Tag: acl.TagGroupObj, Perm: 7}, acl.Entry{Tag: acl.TagMask, Perm: 7}, acl.Entry{Tag: acl.TagOther, Perm: 5})
			},
			args: []string{"-u", "alice", "create", "/srv/shared/notes.md"},
			code: ExitAllowed,
		},
		{
			// Scenario 22: a newline in the name.
			name: "nasty_newline_path",
			setup: func(f *sys.Fake) {
				f.Dir("/srv/up", 0o750, 1001, 1001)
				f.File("/srv/up/a\nb.txt", 0o640, 1001, 1001, "")
			},
			args: []string{"--all", "-u", "www-data", "read", "/srv/up/a\nb.txt"},
			code: ExitDenied,
		},
		{
			name: "missing_did_you_mean",
			setup: func(f *sys.Fake) {
				f.File("/srv/nginx/nginx.conf", 0o644, 0, 0, "")
			},
			args: []string{"-u", "www-data", "read", "/srv/nginx/ngnix.conf"},
			code: ExitDenied,
		},
		{
			name: "symlink_ok",
			setup: func(f *sys.Fake) {
				f.File("/usr/bin/ls", 0o755, 0, 0, "")
				f.Symlink("/bin", "usr/bin", 0, 0)
			},
			args: []string{"exec", "/bin/ls"},
			code: ExitAllowed,
		},
		{
			name: "symlink_loop",
			setup: func(f *sys.Fake) {
				f.Symlink("/srv/a", "b", 0, 0)
				f.Symlink("/srv/b", "a", 0, 0)
			},
			args: []string{"read", "/srv/a"},
			code: ExitDenied,
		},
	}
	for _, tt := range tests {
		runScenario(t, tt.name, tt.setup, tt.args, tt.code)
	}
}
