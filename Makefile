# nodary
#
# One artifact, four channels (docs/adr/0004-release-artifacts-and-channels.md).
# `make dist` cross-compiles the binary; the wheel and npm targets package that
# same binary rather than building anything of their own.

# One version source for the whole tree. install.sh carries its own literal
# because it is fetched standalone and cannot read a file from the repo; the
# release pipeline stamps it from this same value.
VERSION ?= $(shell cat VERSION)
GO      ?= go
DIST    ?= dist

PKG     := github.com/nodarynet/nodary
LDFLAGS := -s -w -X $(PKG)/internal/buildinfo.Version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.DEFAULT_GOAL := help
.PHONY: help build test check fmt vet dist wheels npm packages manifest manifest-check test-install test-packages clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary for this host into $(DIST)/
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/nodary ./cmd/nodary
	@echo "built $(DIST)/nodary"

test: ## Run the Go test suite
	$(GO) test ./...

fmt: ## Format all Go source
	gofmt -w .

vet: ## Run go vet
	$(GO) vet ./...

check: fmt-check vet test ## Everything CI runs on a pull request

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

manifest: ## Regenerate the component manifest from upstream releases
	python3 hack/update-manifest.py

manifest-check: ## Fail if the component manifest is out of date
	python3 hack/update-manifest.py --check

# CGO_ENABLED=0 is what makes these genuinely static and cross-compilable
# without a toolchain per target (ADR 0002).
dist: ## Cross-compile release binaries for every supported platform
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/nodary-$(VERSION)-$$os-$$arch; \
		echo "  building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/nodary || exit 1; \
	done
	@echo "binaries in $(DIST)/"

wheels: dist ## Build PyPI wheels around the release binaries
	python3 packaging/pypi/build_wheels.py --version $(VERSION) --dist $(DIST)

npm: dist ## Assemble the npm packages around the release binaries
	python3 packaging/npm/build_packages.py --version $(VERSION) --dist $(DIST)

packages: wheels npm ## Build every distribution channel

test-install: ## End-to-end test of install.sh, including tamper rejection
	sh hack/test-install.sh

clean: ## Remove build output
	rm -rf $(DIST)

test-packages: ## Verify the built wheels and npm packages install and run
	sh hack/test-packages.sh --version $(VERSION)
