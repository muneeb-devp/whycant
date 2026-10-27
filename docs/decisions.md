# Design decisions

Choices not covered by the project brief, with the reason for each.

## Shared types live in `internal/core`
`Action`, `Perm` and later `Subject`, `Node` and `Finding` are needed by
`walk`, `checks`, `engine`, `fix` and `report`. A separate leaf package avoids
import cycles.

## `append` action
The brief's scenario 10 ("append-only blocks write, not append") needs a way
to ask about appending. `append` needs `w` like `write`, but passes on
append-only (`a`) files. It has no short alias, to avoid confusion with `-a`.

## `-u` defaults to the real uid
`SUDO_USER` is ignored: `sudo whycant read x` checks root. Use `-u` to check
someone else.

## Flag conflicts are usage errors
`--pid` with `--user`/`--group`, and `--json` with `--quiet`, exit 2 rather
than silently preferring one.

## `sys.Real` refuses to open anything but regular files and directories
`InodeFlags` and `ReadHead` must open the file. Opening a device or FIFO can
have side effects (tape rewind, blocking writers), which would break the
read-only rule. Files are opened with `O_NOFOLLOW|O_NONBLOCK` and re-checked
with `fstat`.

## Errors from `sys`
Permission and existence problems are returned as errnos, matched with
`errors.Is(err, fs.ErrPermission)` / `fs.ErrNotExist`. Conditions that are
not errnos everywhere use sentinels: `sys.ErrNoAttr`, `sys.ErrNotSupported`
and `sys.ErrCommandNotFound`.

## Release signing
Cosign signs keyless through GitHub Actions OIDC, so no signing key secret
is needed. The Homebrew tap needs a `HOMEBREW_TAP_TOKEN` secret and a
`muneeb-devp/homebrew-tap` repository; its GoReleaser section is skipped
until that token exists.

## `sys.System` gained `Getgid` and `Getwd`
The current user's primary group is not always in `getgroups()`, and
relative paths need the working directory. Both go through `sys` so tests
stay fake-backed.

## Current user = the session's real groups
Without `-u`, the subject's groups come from the running process, not from
`/etc/group`, because that is what the kernel uses. Configured-but-inactive
groups are the stale-group check (M4).

## Fix suggestions
- No `chmod o+...` fix: it opens the path to every user. An ACL for the one
  subject is always offered first instead.
- A group-membership fix is only offered when the owning group's bits
  actually grant what is needed.
- The note says "restart the service afterwards" for `-u` subjects and "log
  out and back in afterwards" for the current user.

## Unimplemented flags fail loudly
Until their milestone lands, `create`, `delete`, `--json`, `--pid` and
`--verify` exit 2 with "not implemented yet" instead of being ignored.

## Symlinks before M2
A symlinked component is reported as `unknown` (exit 3) rather than guessed.

## Control characters in output are escaped
Human output escapes control characters other than newline as `\xNN`, so a
file name cannot inject terminal escape sequences. Fix commands with control
characters are handled with the shell-quoting work in M2.

## `list` without `x` is a warning
Listing names succeeds with `r` alone, so it is not a blocker; whycant warns
that entries cannot be opened or inspected.

## Symlink display and paths
Each node shows its physical path. A followed symlink is its own row
(`/bin  lrwxrwxrwx  ✓ → usr/bin`) and the link target's directories follow
it. The verdict line keeps the path exactly as the user typed it (made
absolute). Directories already in the chain are not repeated when a link
leads back through them.

## Final symlinks
Followed for every action except `delete`, which acts on the link itself
(like `rm`).

## `create` on an existing path
Reported as info ("already exists"); the verdict covers adding entries to
the parent. `fs.protected_regular`/`protected_fifos` are checked for that
case because `O_CREAT` opens of existing files in sticky dirs are what they
restrict.

## `fs.protected_hardlinks`
Not checked: no whycant action creates hard links.

## Unknown sysctls
If `/proc/sys/fs/protected_*` cannot be read, whycant assumes the kernel and
systemd default (on) and marks the finding `likely`.

## ACL fixes keep existing access
A new named-user ACL entry replaces the group/other bits for that user, so
the suggested entry is the permissions they already had plus what is
missing (`u:alice:rw`, not `u:alice:w`). For a mask problem the fix widens
the mask (`setfacl -m m::rw`).

## Filesystem notes
Synthetic-permission filesystems (vfat, exfat, ntfs, ...) and network
filesystems get a warning on the target (or on the parent for `create`).
DAC findings on network filesystems are `likely`, not `certain`. Overlay is
mentioned only with `-v`, since it is everywhere in containers.

## Display of hostile names
Paths with control characters are shown escaped (`a\nb`) everywhere in the
human output. Fix commands quote them with `$'...'` and octal escapes, which
POSIX.1-2024 and all common shells understand.

## Integration tests
`make integration` builds `test/integration/Dockerfile` (golang + acl,
attr, e2fsprogs) and runs the scenarios privileged on an ext4 loop mount, so
ACLs and `chattr` behave as on a real disk. Scenario 4 (stale groups)
needs a crafted login session and is covered by unit tests only.

## Stale groups
Detected for the current user (session groups vs. the user database) and,
with `--pid`, for a process (its groups vs. the database). When a stale
group would grant the access, the blocker explains that the session or
service predates the group change and suggests `newgrp`/re-login or a
restart; `usermod` is not suggested, since the user is already a member.

## Privileged groups are never suggested
Fixes never suggest joining root, wheel, sudo, admin, adm, shadow, docker,
disk, kmem, lxd, libvirt or systemd-journal: membership grants far more than
access to one file.

## SELinux and AppArmor
whycant does not evaluate policy. It reports the SELinux mode, compares the
file's type with `matchpathcon -n`, and searches the last day of
`/var/log/audit/audit.log` (or the audit journal) for AVC denials matching
the path, or the inode number together with the file name. AppArmor
denials are searched in `journalctl -k` (or `dmesg`) by full path. Recent
denials while enforcing make a `likely` blocker ("probably cannot"). When
SELinux is active but its mode cannot be read, whycant warns instead of
returning `unknown`, so an unreadable sysfs does not hide the DAC answer.
SELinux being enforcing is always mentioned under "Also noticed"; AppArmor
only when it logged denials, since it confines programs, not users.

## Containers and user namespaces
Detected from /.dockerenv, /run/.containerenv, /proc/1/cgroup and
/proc/1/environ, and a non-identity /proc/self/uid_map. Info only.

## `--pid`
Uses the process's filesystem uid/gid (the 4th Uid/Gid fields of
/proc/<pid>/status), which is what the kernel checks file access against,
its supplementary groups, CapEff and /proc/<pid>/attr/current as the label.
`--pid` cannot be combined with `-u`/`-g`.

## `--verify`
- Needs root; without it whycant exits 2 before doing any work.
- The probe re-executes the whycant binary as `__probe <action> <path>` with
  `SysProcAttr.Credential` set to the subject's uid, gid and groups, and
  calls `faccessat(AT_FDCWD, path, mode, 0)`. Flags are 0, not
  `AT_EACCESS`: in the probe real and effective ids are the same, and
  x/sys/unix emulates `AT_EACCESS` in userspace (ignoring ACLs) on kernels
  without faccessat2.
- create and delete probe `W_OK|X_OK` on the parent directory.
- The comparison is fair: whycant re-runs its analysis limited to the rules
  access(2) applies (path lookup, mount ro/noexec/FUSE, immutable, protected
  symlinks, DAC/ACL, file type ignored). Sticky directories, append-only
  writes, a script's read bit, interpreters and loaders, and LSM decisions
  for another program are not visible to access(2) and are left out.
- Processes with capabilities other than none (non-root) or full (root)
  cannot be reproduced, so verify reports that instead of guessing.
- A disagreement exits 4 and asks for a bug report with `--json` output.
- The subject must be able to execute the whycant binary itself; install it
  somewhere like /usr/local/bin.

## Completions
`whycant completion bash|zsh|fish` prints static scripts. The non-Linux stub
also answers it, so release packaging can generate completions on any
build machine.

## Release
- GoReleaser builds linux/amd64, arm64, armv7 and riscv64 static binaries,
  tar.gz archives with completions and the man page, `.deb`/`.rpm`/`.apk`
  via nfpm, checksums, syft SBOMs and a keyless cosign signature of the
  checksum file (GitHub OIDC; no key secret).
- The Homebrew formula uses GoReleaser's `brews` (formula) section even
  though it is deprecated in favor of casks: casks are macOS-only and
  whycant is Linux-only. Uploading needs a `HOMEBREW_TAP_TOKEN` secret and
  the `muneeb-devp/homebrew-tap` repository; without the secret the upload
  is skipped and the release still succeeds.
- `make release-snapshot` and `make demo` fall back to the official
  goreleaser and vhs container images when the tools are not installed.
- The demo's hidden setup removes the recording container's `/.dockerenv`
  so the GIF is about file permissions, not the container note.

## Paths are not cleaned
`..` is resolved physically during the walk, after symlinks (`/tmp/link/..`
is the parent of the link's target, as for the kernel), so the user's path
is never `path.Clean`ed. A trailing `/` (or `/.`) requires the target to be a
directory.

## Kernel corner cases (from review)
- ACLs are only consulted when the mode's group bits (the mask) are not
  empty, as in `acl_permission_check()`.
- Capability overrides apply per request, as in `generic_permission()`:
  `CAP_DAC_READ_SEARCH` covers read-only file requests and directory
  requests without `w`. A script's `x` and `r` are separate requests.
- Read-only mounts do not stop writes to devices, FIFOs or sockets.
- FUSE without `allow_other` needs both `user_id` and `group_id` to match.
- An O_CREAT open of another user's device in a sticky world-writable
  directory is a `likely` blocker (behavior differs across kernel versions).
- `#!` parsing follows binfmt_script exactly (256-byte buffer, NUL ends
  names); ELF requires an exact `e_phentsize` and a NUL-terminated PT_INTERP.
