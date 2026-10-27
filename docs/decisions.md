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
