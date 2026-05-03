# Linux PAM OIDC Plugin

## Project Overview

A Linux PAM module that authenticates users via Google OIDC using the OAuth 2.0 Device Authorization Grant (RFC 8628). Built as a standalone Go binary invoked by `pam_exec.so`.

## Build & Test

```bash
make clean      # Delete and recreate ./bin
make lint       # Run go vet -v ./... and govulncheck
make test       # Run all tests (unit + integration + e2e) with race detector
make build      # Build binary to ./bin/pam-oidc
make release    # Bump patch version, build linux/amd64 + linux/arm64
```

## Architecture

- **`cmd/pam-oidc/`** - Binary entry point
- **`internal/config/`** - YAML configuration loading and validation
- **`internal/oidc/`** - Device authorization flow and ID token validation
- **`internal/pam/`** - PAM I/O abstraction and authentication orchestration
- **`internal/user/`** - Email-to-Linux-user mapping
- **`tests/integration/`** - Integration tests with mock OIDC server
- **`tests/e2e/`** - End-to-end binary subprocess tests

## Conventions

- Go 1.26+
- No CGo - pure Go for clean cross-compilation
- All packages must have `_test.go` files; target 98%+ coverage
- Use `internal/` to prevent external imports
- Config file: YAML format at `/etc/pam-oidc/config.yaml`
- Binary communicates via stdin/stdout/stderr + exit codes
- Tests use `httptest.Server` for mock OIDC endpoints
- E2E tests build and exec the binary as a subprocess

## Testing

- **Unit tests**: Per-package, mock all external dependencies
- **Integration tests**: `tests/integration/` - full flow with mock HTTP server
- **E2E tests**: `tests/e2e/` - compiled binary with stdin/stdout/stderr pipes
- Run all: `make test`
- Coverage report: `go tool cover -html=coverage.out`

## Dependencies

- `gopkg.in/yaml.v3` - config parsing
- `github.com/golang-jwt/jwt/v5` - JWT validation
- Standard library for HTTP, crypto, testing
