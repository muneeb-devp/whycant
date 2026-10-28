# Security policy

## Supported versions

Only the latest release gets security fixes. Upgrade with `apt upgrade`,
`dnf upgrade` or `brew upgrade`, or download it from the
[releases page](https://github.com/muneeb-devp/whycant/releases/latest).

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/muneeb-devp/whycant/security/advisories/new)
with the affected version, how to reproduce it, and what an attacker gains.

You should get a reply within 7 days. Once a fix is released, the advisory is
published with credit to you, unless you would rather stay anonymous.

## What counts

whycant promises to be read-only, so these are vulnerabilities:

- anything that makes whycant change the system: write, chmod, chown,
  setxattr, mount, or anything else beyond reading;
- `--verify` doing anything other than `access(2)` as the subject, or keeping
  privileges it should have dropped;
- a suggested fix command that does something other than what its description
  says, for example through quoting or a crafted file name;
- terminal escape sequences from file names or logs reaching the terminal;
- a problem with the release artifacts, their signatures, or the apt, dnf or
  Homebrew repositories.

A wrong answer about whether access is allowed is a bug, not a vulnerability:
please open a normal issue, ideally with `whycant --json` output.

## Verifying downloads

Release checksums are signed with [cosign](https://github.com/sigstore/cosign)
(keyless, from this repository's release workflow); see the README. apt and
dnf packages are signed with the key at
<https://muneeb-devp.github.io/whycant/whycant.asc>, fingerprint
`ADE3 C9A8 85F1 5561 1D03  6C64 42AC 9731 C68D F4AF`.
