.PHONY: all
all: build govulncheck semgrep

.PHONY: build
build: tidy fmt lint test
	CGO_ENABLED=0 \
	go build -buildmode=pie -trimpath -mod=readonly -ldflags="-s -w" -o bin/hhaudit

.PHONY: debug-build
debug-build: tidy fmt lint test
	go build -gcflags="all=-N -l" -o bin/hhaudit

.PHONY: local-release
local-release: tidy fmt lint test
	goreleaser release --snapshot --clean

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: ci-tidy
ci-tidy:
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
