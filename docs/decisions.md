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
