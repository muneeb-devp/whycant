//go:build integration

package integration

import (
	"debug/elf"
	"os"
	"runtime"

	"github.com/muneeb-devp/whycant/internal/binfmt"
)

// asNobody runs whycant itself as an unprivileged user.
var asNobody = []string{"--reuid=65534", "--regid=65534", "--clear-groups"}

// foreignMachine is an architecture this host does not run natively.
func foreignMachine() (elf.Machine, string) {
	if runtime.GOARCH == "arm64" {
		return elf.EM_X86_64, "x86_64"
	}
	return elf.EM_AARCH64, "aarch64"
}

func writeELF(path string, machine elf.Machine, interp string) error {
	return os.WriteFile(path, binfmt.MinimalELF(64, machine, interp), 0o755)
}

func nativeMachine() elf.Machine {
	m, _ := binfmt.HostMachine(runtime.GOARCH)
	return m
}

func init() {
	foreign, name := foreignMachine()
	qemu := "/proc/sys/fs/binfmt_misc/qemu-" + name
	scenarios = append(scenarios,
		scenario{
			name:  "12_script_not_readable",
			setup: `printf '#!/bin/sh\necho hi\n' > $W/s.sh && chmod 711 $W/s.sh && cp $W/s.sh $W/ok.sh && chmod 755 $W/ok.sh`,
			runs: []run{
				{args: []string{"-u", "www-data", "exec", "$W/s.sh"}, code: 1},
				{args: []string{"-u", "www-data", "exec", "$W/ok.sh"}, code: 0},
			},
		},
		scenario{
			name:  "13_script_crlf",
			setup: `printf '#!/bin/sh\r\necho hi\r\n' > $W/crlf.sh && chmod 755 $W/crlf.sh`,
			runs:  []run{{args: []string{"-u", "alice", "exec", "$W/crlf.sh"}, code: 1}},
		},
		scenario{
			name: "14_missing_interpreter",
			setup: `printf '#!/opt/nowhere/python9\n' > $W/a.py && chmod 755 $W/a.py
printf '#!/usr/bin/env no-such-tool-xyz\n' > $W/b.sh && chmod 755 $W/b.sh
printf '#!/usr/bin/env bash\necho hi\n' > $W/c.sh && chmod 755 $W/c.sh`,
			runs: []run{
				{args: []string{"-u", "alice", "exec", "$W/a.py"}, code: 1},
				{args: []string{"-u", "alice", "exec", "$W/b.sh"}, code: 1},
				{args: []string{"-u", "alice", "exec", "$W/c.sh"}, code: 0},
			},
		},
		scenario{
			name:     "15_wrong_arch",
			requires: "! test -e " + qemu,
			setup:    `true`,
			prepare:  func(w string) error { return writeELF(w+"/foreign", foreign, "") },
			runs:     []run{{args: []string{"exec", "$W/foreign"}, code: 1}},
		},
		scenario{
			name:     "15_wrong_arch_emulated",
			requires: "test -e " + qemu,
			setup:    `true`,
			prepare:  func(w string) error { return writeELF(w+"/foreign", foreign, "") },
			runs:     []run{{args: []string{"exec", "$W/foreign"}, code: 0}},
		},
		scenario{
			name:    "16_missing_loader",
			setup:   `true`,
			prepare: func(w string) error { return writeELF(w+"/app", nativeMachine(), "/lib/ld-whycant-missing.so.1") },
			runs: []run{
				{args: []string{"exec", "$W/app"}, code: 1},
				{args: []string{"-u", "www-data", "exec", "/bin/ls"}, code: 0},
			},
		},
	)
}

// scenarios mirrors the brief's required list (section 7). Scenario 4
// (stale groups) needs a crafted login session and is unit-tested only.
var scenarios = []scenario{
	{
		name: "01_parent_missing_x",
		setup: `mkdir -p $W/app/config && echo x > $W/app/config/db.yml
chown -R deploy:deploy $W/app && chmod 750 $W/app $W/app/config && chmod 640 $W/app/config/db.yml`,
		runs: []run{
			{args: []string{"-u", "www-data", "read", "$W/app/config/db.yml"}, code: 1},
			{args: []string{"-u", "deploy", "read", "$W/app/config/db.yml"}, code: 0},
		},
	},
	{
		name:  "02_owner_precedence",
		setup: `touch $W/notes && chown alice:alice $W/notes && chmod 047 $W/notes`,
		runs:  []run{{args: []string{"-u", "alice", "read", "$W/notes"}, code: 1}},
	},
	{
		name:  "03_group_grants",
		setup: `touch $W/report && chown root:deploy $W/report && chmod 640 $W/report`,
		runs: []run{
			{args: []string{"-u", "alice", "read", "$W/report"}, code: 0},
			{args: []string{"-u", "www-data", "read", "$W/report"}, code: 1},
		},
	},
	{
		name:  "05_acl_named_user",
		setup: `touch $W/secret && chmod 600 $W/secret && setfacl -m u:www-data:r $W/secret`,
		runs: []run{
			{args: []string{"-u", "www-data", "read", "$W/secret"}, code: 0},
			{args: []string{"-u", "alice", "read", "$W/secret"}, code: 1},
		},
	},
	{
		name:  "06_acl_mask",
		setup: `touch $W/log && chmod 600 $W/log && setfacl -m u:www-data:rw $W/log && setfacl -m m::r $W/log`,
		runs: []run{
			{args: []string{"-u", "www-data", "write", "$W/log"}, code: 1},
			{args: []string{"-u", "www-data", "read", "$W/log"}, code: 0},
		},
	},
	{
		name: "07_ro_bind_mount",
		setup: `mkdir -p $W/src $W/dst && touch $W/src/f && chmod 666 $W/src/f
mount --bind $W/src $W/dst && mount -o remount,ro,bind $W/dst`,
		cleanup: `umount $W/dst`,
		runs: []run{
			{args: []string{"-u", "alice", "write", "$W/dst/f"}, code: 1},
			{args: []string{"-u", "alice", "write", "$W/src/f"}, code: 0},
		},
	},
	{
		name: "08_noexec_mount",
		setup: `mkdir -p $W/m && mount -t tmpfs -o noexec tmpfs $W/m
printf '#!/bin/sh\necho hi\n' > $W/m/run.sh && chmod 755 $W/m/run.sh`,
		cleanup: `umount $W/m`,
		runs:    []run{{args: []string{"-u", "alice", "exec", "$W/m/run.sh"}, code: 1}},
	},
	{
		name:    "09_immutable",
		setup:   `touch $W/pinned && chmod 666 $W/pinned && chattr +i $W/pinned`,
		cleanup: `chattr -i $W/pinned`,
		runs: []run{
			{args: []string{"-u", "root", "write", "$W/pinned"}, code: 1},
			{args: []string{"-u", "root", "delete", "$W/pinned"}, code: 1},
			{args: []string{"-u", "root", "read", "$W/pinned"}, code: 0},
		},
	},
	{
		name:    "10_append_only",
		setup:   `touch $W/trail && chmod 666 $W/trail && chattr +a $W/trail`,
		cleanup: `chattr -a $W/trail`,
		runs: []run{
			{args: []string{"-u", "alice", "write", "$W/trail"}, code: 1},
			{args: []string{"-u", "alice", "append", "$W/trail"}, code: 0},
		},
	},
	{
		name:  "11_sticky_dir",
		setup: `mkdir -p $W/tmp && chmod 1777 $W/tmp && touch $W/tmp/f && chown alice $W/tmp/f`,
		runs: []run{
			{args: []string{"-u", "www-data", "delete", "$W/tmp/f"}, code: 1},
			{args: []string{"-u", "alice", "delete", "$W/tmp/f"}, code: 0},
		},
	},
	{
		name: "17_symlink_chain",
		setup: `mkdir -p $W/rel/v2/static && touch $W/rel/v2/static/index.html
chown -R deploy:deploy $W/rel && chmod 700 $W/rel && ln -s $W/rel/v2 $W/current`,
		runs: []run{
			{args: []string{"-u", "www-data", "read", "$W/current/static/index.html"}, code: 1},
			{args: []string{"-u", "deploy", "read", "$W/current/static/index.html"}, code: 0},
		},
	},
	{
		name:     "18_protected_symlinks",
		requires: `test "$(cat /proc/sys/fs/protected_symlinks)" != 0`,
		setup: `mkdir -p $W/tmp && chmod 1777 $W/tmp && touch $W/target && chmod 644 $W/target
ln -s $W/target $W/tmp/link && chown -h alice $W/tmp/link`,
		runs: []run{
			{args: []string{"-u", "www-data", "read", "$W/tmp/link"}, code: 1},
			{args: []string{"-u", "alice", "read", "$W/tmp/link"}, code: 0},
		},
	},
	{
		name: "19_root_dac_bypass",
		setup: `touch $W/zero && chmod 000 $W/zero && touch $W/noexec && chmod 644 $W/noexec
mkdir -p $W/src $W/ro && touch $W/src/f && mount --bind $W/src $W/ro && mount -o remount,ro,bind $W/ro`,
		cleanup: `umount $W/ro`,
		runs: []run{
			{args: []string{"-u", "root", "read", "$W/zero"}, code: 0},
			{args: []string{"-u", "root", "exec", "$W/noexec"}, code: 1},
			{args: []string{"-u", "root", "write", "$W/ro/f"}, code: 1},
		},
	},
	{
		name:  "20_cannot_inspect",
		setup: `mkdir -p $W/priv/inner && touch $W/priv/inner/key && chmod 700 $W/priv`,
		runs: []run{
			{args: []string{"-u", "root", "read", "$W/priv/inner/key"}, code: 3, as: asNobody},
			{args: []string{"-u", "root", "read", "$W/priv/inner/key"}, code: 0},
		},
	},
	{
		name:  "21_create_without_x",
		setup: `mkdir -p $W/inbox && chown deploy:deploy $W/inbox && chmod 772 $W/inbox`,
		runs: []run{
			{args: []string{"-u", "www-data", "create", "$W/inbox/new"}, code: 1},
			{args: []string{"-u", "deploy", "create", "$W/inbox/new"}, code: 0},
		},
	},
	{
		name: "22_nasty_path",
		setup: `f="$W/it's a -file; rm -rf ~"; touch "$f" && chown deploy "$f" && chmod 600 "$f"
g="$W/new
line"; touch "$g" && chmod 644 "$g"`,
		runs: []run{
			{args: []string{"-u", "www-data", "read", "--", "$W/it's a -file; rm -rf ~"}, code: 1},
			{args: []string{"-u", "www-data", "read", "--", "$W/new\nline"}, code: 0},
		},
	},
}

// Kernel corner cases found in review; each failed before it was fixed.
func init() {
	scenarios = append(scenarios,
		scenario{
			name: "r1_acl_empty_mask",
			// chmod g= empties the mask, so the kernel ignores the ACL.
			setup: `touch $W/f && setfacl -m u:alice:r $W/f && chmod 604 $W/f`,
			runs:  []run{{args: []string{"-u", "alice", "read", "$W/f"}, code: 0}},
		},
		scenario{
			name: "r2_physical_dotdot",
			setup: `mkdir -p $W/real/sub && touch $W/real/target && ln -s $W/real/sub $W/link
mkdir -p $W/locked && chmod 700 $W/locked && ln -s $W/locked $W/via`,
			runs: []run{
				{args: []string{"-u", "alice", "read", "$W/link/../target"}, code: 0},
				{args: []string{"-u", "alice", "traverse", "$W/via/.."}, code: 1},
			},
		},
		scenario{
			name:  "r3_trailing_slash",
			setup: `touch $W/file && chmod 644 $W/file && mkdir $W/dir`,
			runs: []run{
				{args: []string{"-u", "alice", "read", "$W/file/"}, code: 1},
				{args: []string{"-u", "alice", "list", "$W/dir/"}, code: 0},
			},
		},
		scenario{
			name: "r4_ro_mount_fifo",
			setup: `mkdir -p $W/src $W/ro && mkfifo -m 666 $W/src/pipe && touch $W/src/file && chmod 666 $W/src/file
mount --bind $W/src $W/ro && mount -o remount,ro,bind $W/ro`,
			cleanup: `umount $W/ro`,
			runs: []run{
				{args: []string{"-u", "alice", "write", "$W/ro/pipe"}, code: 0},
				{args: []string{"-u", "alice", "write", "$W/ro/file"}, code: 1},
			},
		},
		scenario{
			name:  "r5_wrong_type",
			setup: `touch $W/plain && chmod 644 $W/plain && mkdir $W/ro_dir && chmod 555 $W/ro_dir`,
			runs: []run{
				{args: []string{"-u", "alice", "traverse", "$W/plain"}, code: 1},
				{args: []string{"-u", "alice", "write", "$W/ro_dir"}, code: 1},
			},
		},
		scenario{
			name:    "r6_append_only_dir",
			setup:   `mkdir $W/logs && touch $W/logs/old && chattr +a $W/logs`,
			cleanup: `chattr -a $W/logs`,
			runs: []run{
				{args: []string{"-u", "root", "delete", "$W/logs/old"}, code: 1},
				{args: []string{"-u", "root", "create", "$W/logs/new"}, code: 0},
			},
		},
	)
}
