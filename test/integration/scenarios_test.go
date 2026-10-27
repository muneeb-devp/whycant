//go:build integration

package integration

// asNobody runs whycant itself as an unprivileged user.
var asNobody = []string{"--reuid=65534", "--regid=65534", "--clear-groups"}

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
