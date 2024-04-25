.PHONY: all
all: build

.PHONY: build
build: tidy format test
	go build -o bin/hhaudit

.PHONY: release
release: tidy format test
	goreleaser release --snapshot --clean

.PHONY: format
format:
	gofmt -s -w .

.PHONY: test
test:
	go test -cover

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean: tidy
	rm -rf bin/ dist/

.PHONY: run
run:
	go run main.go
