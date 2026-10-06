.PHONY: all
all: build govulncheck semgrep

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
	@echo "  semgrep        to run SAST suite"
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
	go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...

.PHONY: semgrep
semgrep:
	semgrep --config 'p/default' --error

.PHONY: test
test:
	go test -cover

.PHONY: clean
clean: tidy
	rm -rf bin/ dist/

.PHONY: run
run:
	go run main.go
