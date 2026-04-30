VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

CLI_PKG    := ./cmd/observe
SERVER_PKG := ./cmd/server
DIST       := dist

.PHONY: all build-cli build-server build-all cross-compile clean test lint

all: build-all

## Build CLI for the host OS
build-cli:
	go build $(LDFLAGS) -o $(DIST)/observe$(EXT) $(CLI_PKG)

## Build web server for the host OS
build-server:
	go build $(LDFLAGS) -o $(DIST)/observer-server$(EXT) $(SERVER_PKG)

## Build both binaries for the host OS
build-all: build-cli build-server

## Cross-compile all binaries for Windows / macOS / Linux (amd64 + arm64)
cross-compile:
	@mkdir -p $(DIST)
	# Linux
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observe-linux-amd64             $(CLI_PKG)
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/observe-linux-arm64             $(CLI_PKG)
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observer-server-linux-amd64     $(SERVER_PKG)
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/observer-server-linux-arm64     $(SERVER_PKG)
	# macOS
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observe-darwin-amd64            $(CLI_PKG)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/observe-darwin-arm64            $(CLI_PKG)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observer-server-darwin-amd64    $(SERVER_PKG)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/observer-server-darwin-arm64    $(SERVER_PKG)
	# Windows
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observe-windows-amd64.exe             $(CLI_PKG)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/observer-server-windows-amd64.exe      $(SERVER_PKG)
	@echo "Cross-compilation complete. Binaries in $(DIST)/"

## Run all tests (unit only; use --tags integration for live API tests)
test:
	go test ./...

## Run linter (requires golangci-lint)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed — skipping"; exit 0; }
	golangci-lint run ./...

## Remove built binaries
clean:
	rm -rf $(DIST)

## Download dependencies and tidy go.sum
deps:
	go mod tidy
