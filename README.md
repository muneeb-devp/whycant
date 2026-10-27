# whycant

A Linux permission debugger. Tell it *who* wants to do *what* to *which path*, and it tells you exactly which link in the chain says no, why, and the least-privileged way to fix it.

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

> **Status:** early development. Mode bits, path walking and user/group resolution work today. Symlinks, ACLs, mount options, file attributes, `create`/`delete`, exec deep checks, JSON output and SELinux/AppArmor are on the way.

## Usage

```
whycant [flags] <action> <path>
```

| Action     | Aliases        | Checks                                  |
|------------|----------------|-----------------------------------------|
| `read`     | `r`            | open a file for reading                 |
| `write`    | `w`            | open an existing file for writing       |
| `append`   |                | open an existing file for appending     |
| `exec`     | `x`, `run`     | run a file                              |
| `list`     | `ls`           | list a directory's entries              |
| `traverse` | `cd`           | enter a directory                       |
| `create`   | `mk`, `touch`  | create a new entry (coming soon)        |
| `delete`   | `rm`           | delete or rename an entry (coming soon) |

`-u` checks on behalf of another user; without it, whycant checks the user running it (the real uid, with the session's actual groups; `SUDO_USER` is ignored). `-g` adds groups to try "what if". `-a` reports every problem instead of stopping at the first. Run `whycant --help` for all flags.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | access allowed |
| 1 | access denied |
| 2 | usage error |
| 3 | could not determine: whycant itself could not inspect part of the path (re-run with `sudo`) |
| 4 | `--verify` disagreed with the analysis (please report it) |

whycant is strictly read-only: it never changes files, permissions or mounts.

## Development

```
make build        # static Linux binary in bin/
make test         # unit tests (run on macOS too) + Linux vet
make test-linux   # unit tests inside a Linux container
make lint         # golangci-lint for host and Linux
make integration  # real-kernel scenarios in a privileged container
```

Output tests compare against golden files in `testdata/`; regenerate them with `go test ./internal/cli -update` and review the diff.

## License

MIT
