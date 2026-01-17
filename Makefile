.PHONY: all build test test-v test-race cover cover-html lint fmt vet clean help

# Disable CGO for portable builds and to avoid macOS dyld issues
export CGO_ENABLED=0

# Default target
all: fmt vet lint test build

# Build all packages
build:
	go build ./...

# Run tests
test:
	go test ./...

# Run tests with verbose output
test-v:
	go test -v ./...

# Run tests with race detector (requires CGO)
test-race:
	CGO_ENABLED=1 go test -race ./...

# Run tests with coverage
cover:
	go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

# Generate HTML coverage report
cover-html: cover
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run linter (requires golangci-lint)
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html
	go clean ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  make          - Format, vet, lint, test, and build"
	@echo "  make build    - Build all packages"
	@echo "  make test     - Run tests"
	@echo "  make test-v   - Run tests with verbose output"
	@echo "  make test-race - Run tests with race detector"
	@echo "  make cover    - Run tests with coverage summary"
	@echo "  make cover-html - Generate HTML coverage report"
	@echo "  make lint     - Run golangci-lint"
	@echo "  make fmt      - Format code"
	@echo "  make vet      - Run go vet"
	@echo "  make clean    - Remove build artifacts"
