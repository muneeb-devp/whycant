## What and why

<!-- What does this change, and which problem does it solve? Link the issue: Fixes #123 -->

## Checklist

- [ ] The PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (it becomes the squash commit)
- [ ] `make lint test` passes
- [ ] `make integration` passes, if this touches checks, the walk or `--verify`
- [ ] New checks have unit tests, a golden scenario and an integration scenario ([CONTRIBUTING.md](../CONTRIBUTING.md#how-to-add-a-check))
- [ ] Still read-only, and no new fix suggests `chmod 777`, `chmod -R`, privileged groups or disabling SELinux/AppArmor
- [ ] README, `docs/` and `docs/decisions.md` updated where needed
