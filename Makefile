# whycant build targets. Development happens on macOS too: unit tests run
# natively, while Linux-only code is vetted with GOOS=linux and exercised in
# Docker (test-linux, integration).

GO        ?= go
GOARCH    ?= $(shell $(GO) env GOARCH)
GO_IMAGE  ?= golang:1.27
FUZZTIME  ?= 30s
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X github.com/muneeb-devp/whycant/internal/cli.Version=$(VERSION)

DOCKER_RUN := docker run --rm -v "$(CURDIR)":/src -w /src -e GOFLAGS=-buildvcs=false \
	-v whycant-gomod:/go/pkg/mod -v whycant-gocache:/root/.cache/go-build

.PHONY: all build test test-linux integration lint fmt fuzz demo release-snapshot clean

all: build lint test

## build: static Linux binary for the host architecture in bin/
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/whycant ./cmd/whycant

## test: unit tests on the host, plus a vet pass of the Linux build
test:
	$(GO) test -race ./...
	GOOS=linux $(GO) vet ./...

## test-linux: unit tests (including Linux-only ones) in a container
test-linux:
	$(DOCKER_RUN) $(GO_IMAGE) go test ./...

## integration: scenario tests against a real kernel (needs privileges for chattr/setfacl/mount)
integration:
	docker build -q -t whycant-integration test/integration >/dev/null
	$(DOCKER_RUN) --privileged whycant-integration go test -tags integration -count=1 -v ./test/integration/...

## lint: golangci-lint for the host and for Linux
lint:
	golangci-lint run ./...
	GOOS=linux golangci-lint run ./...

fmt:
	gofumpt -w .

## fuzz: short run of every fuzz target
fuzz:
	@for pkg in $$($(GO) list ./...); do \
		for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "fuzz $$pkg $$f"; \
			$(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

## demo: record docs/demo.gif (uses Docker without vhs)
demo: build
	@if command -v vhs >/dev/null; then vhs docs/demo.tape; else \
		docker run --rm -v "$(CURDIR)":/vhs ghcr.io/charmbracelet/vhs docs/demo.tape; fi

## release-snapshot: build every release artifact locally, unsigned (uses Docker without goreleaser)
release-snapshot:
	@if command -v goreleaser >/dev/null; then \
		goreleaser release --snapshot --clean --skip=sign; \
	else \
		docker run --rm -v "$(CURDIR)":/src -w /src --entrypoint sh goreleaser/goreleaser:latest \
			-c 'git config --global --add safe.directory /src && goreleaser release --snapshot --clean --skip=sign'; \
	fi

clean:
	rm -rf bin dist coverage.out
