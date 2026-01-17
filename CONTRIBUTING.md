# Contributing to device-attestation

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/device-attestation.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Run linter: `golangci-lint run`
7. Commit your changes: `git commit -m "Add feature X"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or later
- golangci-lint (for linting)

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Running Linter

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

## Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` for formatting
- Use `goimports` for import organization
- Write meaningful commit messages
- Add tests for new functionality
- Update documentation as needed

## Pull Request Guidelines

1. **One feature per PR**: Keep pull requests focused on a single change
2. **Write tests**: New features should include tests
3. **Update docs**: Update README.md and code comments as needed
4. **Describe changes**: Write a clear PR description explaining the changes
5. **Keep it small**: Smaller PRs are easier to review

## Reporting Issues

When reporting issues, please include:

- Go version (`go version`)
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant logs or error messages

## Feature Requests

Feature requests are welcome! Please open an issue describing:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build something useful together.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
