# Contributing to whycant

Thanks for helping! Bug reports with `whycant --json` output are especially
welcome, and `--verify` mismatches (exit code 4) are always bugs.

## Ground rules

- **Read-only.** No code path may write, chmod, chown, setxattr, mount or
  otherwise change the system. Only `--verify` changes credentials, inside
  the probe subprocess, and the probe only calls `access(2)`.
- **All OS access goes through `sys.System`** (`internal/sys`). No `os.Stat`,
  `unix.*` or `exec.Command` elsewhere, so every check can be tested
  against `sys.Fake`.
- **Never suggest** `chmod 777`, `chmod -R`, joining privileged groups, or
  disabling SELinux/AppArmor.
- **Be honest.** When kernel behavior is uncertain, use `likely`/`possible`
  confidence or an `unknown` severity rather than guessing.
- **Explain like a patient senior admin**: short sentences that name the
  exact path, user and bit.

## Workflow

1. For anything bigger than a small fix, open an issue first so we can agree
   on the approach.
2. Fork the repository and create a branch from `main`.
3. Make the change, with tests:

   ```sh
   make lint test          # before every commit
   make integration        # for anything that touches checks or the walk (needs Docker)
   ```

4. Open a pull request and fill in the template. `main` is protected: every
   change goes through a pull request, and CI (lint, test, integration, fuzz
   and govulncheck) must pass before it can merge. Pull requests are squash-merged,
   so the **PR title** becomes the commit message.

Commits and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat(checks): add ACL mask evaluation`. New dependencies need a reason in
the PR description. Security problems go through
[private vulnerability reporting](SECURITY.md), not issues or pull requests.
By contributing you agree to the [code of conduct](CODE_OF_CONDUCT.md) and to
license your work under the [MIT license](LICENSE).

## Releasing (maintainers)

Tag `main` and push the tag:

```sh
git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0
```

The release workflow builds and signs the artifacts, publishes the GitHub
release, updates the Homebrew formula and the apt and dnf repositories.
Only maintainers can create `v*` tags.

## How to add a check

1. **Write the tests first.** Add table-driven cases in
   `internal/checks/*_test.go` that build nodes (or a `sys.Fake` tree) and
   assert the severity, summary and fixes.
2. **Add a file in `internal/checks/`** with a type implementing
   `checks.Check`:

   ```go
   type Quota struct{}

   func (Quota) Name() string { return "quota" }
   func (Quota) Applies(ctx *Context, n *core.Node) bool { return modifies(ctx, n) }
   func (Quota) Evaluate(ctx *Context, n *core.Node) []core.Finding { … }
   ```

   Use `Blocker` only when the kernel would refuse, `Warn`/`Info` for
   context, and `Pass` for a summary shown with `-v`. Build fix commands
   with `fix.Command`, which quotes every argument.
3. **Register it** in `checks.Default()` in the right order (things that
   stop root first, then permissions, then subtler rules).
4. **Add a golden scenario** in `internal/cli/scenario_*_test.go` and run
   `go test ./internal/cli -update`; review the new file in `testdata/`.
5. **Add an integration scenario** in `test/integration/scenarios_test.go`:
   a setup script under `$W`, a cleanup for anything mounted, and both a
   denied and an allowed run. Every run is automatically confirmed with
   `--verify`; if `access(2)` cannot see your rule, leave the check out of
   `verify.AccessChecks()` (or skip it when `ctx.AccessOnly` is set).
6. **Document it**: the README's "What it checks" table, and
   `docs/decisions.md` for any non-obvious choice.

## Layout

```
cmd/whycant/       entry point (Linux) and the non-Linux stub
internal/cli/      flags, wiring, exit codes, completions
internal/sys/      the System interface, Real (Linux) and Fake
internal/identity/ users, groups, --pid, stale groups
internal/walk/     kernel-style path resolution into nodes
internal/checks/   one file per check
internal/engine/   runs checks, follows interpreters/loaders, decides the verdict
internal/fix/      shell quoting and fix ranking
internal/report/   human and JSON output
internal/verify/   the __probe subcommand and comparison
internal/acl, mount, binfmt/  parsers (fuzzed)
test/integration/  real-kernel scenarios (make integration)
```
