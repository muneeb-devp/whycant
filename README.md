# whycant

**A Linux permission debugger.** Tell it *who* wants to do *what* to *which path*, and it tells you exactly which link in the chain says no, why, and the least-privileged way to fix it.

![whycant demo](docs/demo.gif)

"Permission denied" can come from a dozen layers: a missing `x` on a parent directory, owner/group/other precedence, an ACL mask, a read-only or `noexec` mount, an immutable file, a sticky `/tmp`, SELinux or AppArmor, a group you were added to after logging in, a script with Windows line endings, a binary for the wrong CPU… `ls -l`, `namei`, `getfacl`, `lsattr`, `findmnt` and `ausearch` each show one slice. whycant walks the whole chain the way the kernel does and gives one answer.

```
$ whycant -u www-data read /srv/app/config/db.yml

✗ www-data (uid 33) cannot read /srv/app/config/db.yml

  /                        drwxr-xr-x  root:root      ✓ traverse
  /srv                     drwxr-xr-x  root:root      ✓ traverse
  /srv/app                 drwxr-x---  deploy:deploy  ✗ traverse   ← blocked here
  /srv/app/config          ·           not evaluated
  /srv/app/config/db.yml   ·           not evaluated

Why
  www-data is not the owner (deploy) and is not in group "deploy",
  so the "other" permissions apply: ---. Entering a directory needs x.

Fixes (safest first)
  1. Grant traverse only to www-data via ACL:
       sudo setfacl -m u:www-data:x /srv/app
  2. Add www-data to the deploy group (restart the service afterwards):
       sudo usermod -aG deploy www-data
```

whycant is **strictly read-only**: it never changes files, permissions, attributes or mounts, not even with `--verify`. It never suggests `chmod 777`, recursive `chmod`, or turning SELinux/AppArmor off.

## Install

Download a package from the [releases page](https://github.com/muneeb-devp/whycant/releases) (`amd64`, `arm64`, `armv7`, `riscv64`):

```sh
# Debian, Ubuntu
sudo apt install ./whycant_*_amd64.deb

# Fedora, RHEL, openSUSE
sudo dnf install ./whycant-*.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted ./whycant_*_x86_64.apk

# Homebrew on Linux
brew install muneeb-devp/tap/whycant

# Anywhere: a single static binary
tar xzf whycant_*_linux_amd64.tar.gz && sudo install whycant /usr/local/bin/

# From source (Go 1.27+)
go install github.com/muneeb-devp/whycant/cmd/whycant@latest
```

Packages include shell completions and a man page. Release checksums are signed with [cosign](https://github.com/sigstore/cosign) (keyless) and every archive has an SBOM:

```sh
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/muneeb-devp/whycant/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

## Usage

```
whycant [flags] <action> <path>
```

| Action     | Aliases            | Asks whether the subject can…                          |
|------------|--------------------|--------------------------------------------------------|
| `read`     | `r`                | open a file for reading                                |
| `write`    | `w`                | open an existing file for writing                      |
| `append`   |                    | open an existing file for appending                    |
| `exec`     | `x`, `run`         | run a file (script interpreters and loaders included)  |
| `list`     | `ls`               | list a directory                                       |
| `traverse` | `cd`               | enter a directory                                      |
| `create`   | `mk`, `touch`      | create a new entry at the path                         |
| `delete`   | `rm`               | delete or rename the entry                             |

| Flag | |
|------|--|
| `-u, --user <name\|uid>` | check on behalf of this user (default: you, with your session's groups) |
| `-g, --group <name\|gid>` | also assume this group, repeatable: "would it work if I added the group?" |
| `-p, --pid <pid>` | use a running process's credentials, capabilities and label |
| `-a, --all` | report every problem, not just the first blocker |
| `-v, --verbose` | show passing checks too |
| `--json` | machine-readable output ([schema](docs/json.md)) |
| `--verify` | confirm the answer with the kernel's own `access(2)`, run as the subject (root only) |
| `--color auto\|always\|never` | default `auto`; honors `NO_COLOR` |
| `-q, --quiet` | only the verdict line |
| `completion bash\|zsh\|fish` | print shell completions |

Examples:

```sh
whycant -u www-data read /srv/app/config/db.yml        # why does nginx get 403?
whycant --pid "$(pidof -s nginx)" read /var/www/index.html
whycant exec ./build.sh                                  # "bad interpreter"? wrong arch?
whycant -u deploy create /srv/releases/new               # can the deploy user write here?
whycant -g docker read /var/run/docker.sock              # what if I join the group?
sudo whycant --verify -u backup read /etc/ssl/private/key.pem
whycant --json delete /tmp/x | jq -r .verdict            # for scripts
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | access allowed |
| 1 | access denied |
| 2 | usage error |
| 3 | could not determine: whycant itself could not inspect part of the path (run it again with `sudo`) |
| 4 | `--verify` disagreed with the analysis: a whycant bug, please [report it](https://github.com/muneeb-devp/whycant/issues) with the `--json` output |

## What it checks

| Layer | What whycant looks at |
|-------|-----------------------|
| Path walk | every component from `/`, `x` on each directory, missing components (with "did you mean"), components whycant itself cannot see |
| Symlinks | followed like the kernel, link targets' directories checked too, loops (40 links), `fs.protected_symlinks` |
| Mode bits | exact owner → group → other precedence, including "the owner gets `---` even though other has `rwx`" |
| POSIX ACLs | parsed from the xattr, evaluated in kernel order, the mask explained; default ACLs on `create` |
| Root and capabilities | `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`; root still needs one `x` bit to run a file |
| Mounts | `ro` (also stops root), `noexec`, `nosuid`, FUSE without `allow_other`; warnings for vfat/exfat/ntfs (fake permissions) and NFS/CIFS (the server decides, root squash) |
| File attributes | immutable (`+i`) and append-only (`+a`), which also stop root |
| Directories | `w`+`x` to create/delete, sticky-bit deletion rules, `fs.protected_regular`/`protected_fifos` |
| Exec | scripts need `r`, CRLF `#!` lines, missing or non-executable interpreters (through `env` too), wrong-architecture binaries (qemu-aware), missing dynamic loaders (the "No such file or directory" for a file that exists) |
| Groups | groups you were added to after logging in, and services started before a group change |
| SELinux | mode, file label vs. policy default (`restorecon`), recent AVC denials for the file |
| AppArmor | recent denials for the path and the profile that caused them |
| Environment | full disks and exhausted inodes, containers and user namespaces |

Results are explained in plain English, and fixes are ranked from safest (an ACL entry for one user, one bit on one file) to broadest (group membership), with paths safely quoted for copy-paste.

## How it compares

| Tool | Shows | whycant adds |
|------|-------|--------------|
| `ls -l` | one file's mode | which class applies to *this* user, and every directory above it |
| `namei -l` | modes along a path | the decision for a given user and action, ACLs, mounts, attributes |
| `getfacl` | the ACL | kernel-order evaluation and the effective permission after the mask |
| `lsattr` | `i` and `a` flags | whether they matter for this action |
| `findmnt` | mount options | which mount holds each component and what `ro`/`noexec` block |
| `ausearch` | raw denials | denials matched to the file, next to the DAC answer |

## JSON

`--json` prints a stable, versioned document with the verdict, the subject, every chain component and the findings with ranked fixes. See [docs/json.md](docs/json.md).

## Development

```sh
make build             # static Linux binary in bin/
make test              # unit tests (also on macOS) + vet for Linux
make test-linux        # unit tests in a Linux container
make lint              # golangci-lint for host and Linux
make integration       # real-kernel scenarios in a privileged container, each confirmed with --verify
make fuzz              # fuzz the ACL, mountinfo, shebang and ELF parsers
make demo              # record docs/demo.gif
make release-snapshot  # build every release artifact locally
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to add a check, [docs/testing.md](docs/testing.md) for the test setup and [docs/decisions.md](docs/decisions.md) for design choices.

## License

MIT
