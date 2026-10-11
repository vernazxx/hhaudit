# SAST: opengrep with every rule source pinned (see AGENTS.md). Dependabot
# can't bump these; update them deliberately and re-verify.
OPENGREP ?= opengrep
OPENGREP_VERSION := v1.30.1
# sha256 of the opengrep_manylinux_x86 asset of OPENGREP_VERSION
OPENGREP_SHA256 := d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4
OPENGREP_DIR ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/hhaudit/opengrep-$(OPENGREP_VERSION)
OPENGREP_RULES_SHA := f1d2b562b414783763fd02a6ed2736eaed622efa
TOB_RULES_SHA := 31390b3a99c04c81522d1b37c8d1900aa2dd4094
SAST_CACHE ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/hhaudit/sast-rules
OPENGREP_RULES := $(SAST_CACHE)/opengrep-rules-$(OPENGREP_RULES_SHA)
TOB_RULES := $(SAST_CACHE)/trailofbits-semgrep-rules-$(TOB_RULES_SHA)

.PHONY: all
all: build govulncheck sast

.PHONY: help
help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  help           to print this help message"
	@echo "  build          to build the binary for production mode"
	@echo "  build-dev      to build the binary for development mode"
	@echo "  local-release  to create a local release"
	@echo "  tidy           to ensure go.mod matches the source in the module"
	@echo "  tidy-ci        to fail if 'make tidy' would change go.mod/go.sum"
	@echo "  fmt            to run the formatter on Go code"
	@echo "  lint           to run the linter on Go code"
	@echo "  govulncheck    to check for known vulnerabilities"
	@echo "  sast           to run the SAST suite (opengrep, pinned rules)"
	@echo "  opengrep-install  to install the pinned, signature-verified opengrep (Linux x86_64)"
	@echo "  test           to run test suite"
	@echo "  clean          to delete the project temporary files"
	@echo "  run            to run the binary"

.PHONY: build
build: tidy fmt lint test
	CGO_ENABLED=0 \
	go build -buildmode=pie -trimpath -mod=readonly -ldflags="-s -w" -o bin/hhaudit

.PHONY: build-dev
build-dev: tidy fmt lint test
	go build -gcflags="all=-N -l" -o bin/hhaudit

.PHONY: local-release
local-release: tidy fmt lint test
	goreleaser release --snapshot --clean

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: tidy-ci
tidy-ci:
	git diff --quiet
	go mod tidy
	git diff --quiet || (echo -e "\nModified files:" && git status --short && echo -e "\nRun 'make tidy' locally and commit the changes.\n" && exit 1)

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: lint
lint:
	golangci-lint cache status
	golangci-lint run -E gosec

.PHONY: govulncheck
govulncheck:
	go tool govulncheck -show verbose ./...

.PHONY: opengrep-install
opengrep-install:
	scripts/install-opengrep.sh $(OPENGREP_VERSION) $(OPENGREP_SHA256) $(OPENGREP_DIR)

.PHONY: sast-rules
sast-rules:
	scripts/fetch-sast-rules.sh https://github.com/opengrep/opengrep-rules.git $(OPENGREP_RULES_SHA) $(OPENGREP_RULES)
	scripts/fetch-sast-rules.sh https://github.com/trailofbits/semgrep-rules.git $(TOB_RULES_SHA) $(TOB_RULES)

.PHONY: sast
sast: sast-rules
	@$(OPENGREP) --version | grep -qx '$(OPENGREP_VERSION:v%=%)' || \
		(echo "opengrep $(OPENGREP_VERSION) required, found $$($(OPENGREP) --version)"; exit 1)
	$(OPENGREP) test .opengrep/
	$(OPENGREP) scan --disable-version-check --error --exclude .opengrep \
		--config $(OPENGREP_RULES)/go \
		--config $(OPENGREP_RULES)/generic/secrets \
		--config $(TOB_RULES)/go \
		--config .opengrep/ \
		.

.PHONY: test
test:
	go test -cover ./...

.PHONY: clean
clean: tidy
	rm -rf bin/ dist/

.PHONY: run
run:
	go run main.go
