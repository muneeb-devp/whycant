# whycant

A Linux permission debugger. Tell it *who* wants to do *what* to *which path*, and it tells you exactly which link in the chain says no, why, and the least-privileged way to fix it.

> **Status:** early development. The CLI parses arguments but does not analyse anything yet.

```
whycant [flags] <action> <path>
```

Actions: `read`, `write`, `append`, `exec`, `list`, `traverse`, `create`, `delete`.

## Development

```
make build        # static Linux binary in bin/
make test         # unit tests (run on macOS too) + Linux vet
make test-linux   # unit tests inside a Linux container
make lint         # golangci-lint for host and Linux
make integration  # real-kernel scenarios in a privileged container
```

## License

MIT
