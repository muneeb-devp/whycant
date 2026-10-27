# Testing whycant

## Unit tests

```
make test          # host (macOS works) + vet for Linux
make test-linux    # the same inside a Linux container, including sys.Real tests
```

Checks are tested against `sys.Fake`, an in-memory filesystem with
configurable owners, modes, xattrs, inode flags, mount tables and recorded
command output. Rendering is covered by golden files in `testdata/`:

```
go test ./internal/cli -update   # regenerate, then review with git diff
```

## Fuzzing

```
make fuzz FUZZTIME=1m
```

Targets: the ACL xattr parser, the mountinfo parser and the shebang parser.

## Integration tests (real kernel)

```
make integration
```

Builds `test/integration/Dockerfile` and runs `go test -tags integration`
in a privileged container. Each scenario in
`test/integration/scenarios_test.go` is a setup script plus whycant runs
with expected exit codes; every run is cross-checked with `--verify`, so
the analysis is compared with the kernel's own answer.

To add one: append to `scenarios` with a setup script that only touches
`$W` (the scenario's directory), a cleanup for anything mounted, and both a
denied and an allowed run where possible.

## SELinux and AppArmor

Covered by unit tests with recorded log fixtures. To try them by hand on a
Fedora VM (SELinux enforcing):

```
sudo mkdir -p /srv/www && echo hi | sudo tee /srv/www/index.html
sudo chcon -t user_home_t /srv/www/index.html   # wrong label on purpose
curl -s localhost/ >/dev/null                    # with httpd serving /srv/www
sudo whycant -u apache read /srv/www/index.html  # expect a label mismatch and an AVC denial
```
