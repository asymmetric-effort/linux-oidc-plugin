# Architecture

## Component Overview

```
+-------------------+
|   pam_exec.so     |   PAM invokes the binary as a child process
+--------+----------+
         |
         v
+--------+----------+
|  cmd/pam-oidc/    |   Binary entry point -- wires dependencies, calls handler
+--------+----------+
         |
         v
+--------+----------+
|  internal/pam/    |   Authentication orchestration + I/O abstraction
|  - handler.go     |     Coordinates the full auth flow
|  - io.go          |     Reads stdin, writes stdout/stderr, leveled logging
+--------+----------+
         |
    +----+----+
    |         |
    v         v
+---+------+ ++-----------+  +----------------+
| oidc/    | | user/      |  | config/        |
| device.go| | mapper.go  |  | config.go      |
| token.go | +------------+  +----------------+
+----------+
  |    |
  |    +--- JWT/JWKS validation (token.go)
  +-------- Device Authorization Grant (device.go)
```

## Data Flow

The plugin follows a linear request-response flow through clearly separated
components.

### 1. Startup

1. PAM calls `pam_exec.so`, which forks and executes `/usr/local/bin/pam-oidc`.
2. `cmd/pam-oidc/main.go` loads configuration from
   `/etc/pam-oidc/config.yaml` (or the path in `PAM_OIDC_CONFIG`).
3. Dependencies are constructed: OIDC client, token validator, user mapper, I/O
   handler.
4. The `pam.Handler.Authenticate()` method is called.

### 2. Authentication

```
handler.Authenticate(ctx)
  |
  +--> io.ReadUsername()
  |      Read PAM_USER env var, or fall back to stdin
  |
  +--> oidcClient.RequestDeviceCode(clientID, clientSecret, scopes)
  |      POST to device authorization endpoint
  |      Returns: device_code, user_code, verification_uri
  |
  +--> io.DisplayMessage(verification_uri, user_code)
  |      Write URL and code to stdout for the user to see
  |
  +--> oidcClient.PollForToken(clientID, clientSecret, deviceCode, interval, timeout)
  |      Poll token endpoint every `interval` seconds
  |      Handle: authorization_pending, slow_down, access_denied, expired_token
  |      Returns: id_token (JWT)
  |
  +--> tokenValidator.ValidateIDToken(rawToken, expectedAudience)
  |      Fetch JWKS from Google, verify RS256 signature
  |      Validate: issuer, audience, expiry, email_verified
  |      Returns: Claims{email, subject, ...}
  |
  +--> userMapper.MapEmailToUser(email)
  |      email_prefix: strip domain (alice@example.com -> alice)
  |      static: lookup in configured mapping table
  |
  +--> Compare mapped username with PAM_USER
  |
  +--> Return exit code
```

### 3. Termination

The binary exits with a code that `pam_exec.so` interprets:

| Exit Code | Constant | Meaning |
|-----------|----------|---------|
| 0 | `ExitSuccess` | Authentication succeeded. User identity confirmed. |
| 1 | `ExitAuthError` | Authentication failed. User denied, token invalid, or username mismatch. |
| 2 | `ExitSysError` | System error. Config unreadable, network failure, or internal fault. |

PAM maps exit code 0 to `PAM_SUCCESS` and any nonzero code to
`PAM_AUTH_ERR`.

## Why pam_exec.so Instead of a CGo Shared Object

Traditional PAM modules are `.so` shared libraries loaded by `libpam`. Writing
one in Go would require CGo, which introduces several problems:

| Concern | CGo shared library | pam_exec.so + Go binary |
|---------|--------------------|------------------------|
| **Build complexity** | Requires `gcc`, correct glibc version, CGo cross-compile toolchain | `GOOS=linux GOARCH=amd64 go build` |
| **Runtime linking** | Loaded into every PAM-using process (sshd, login, sudo); symbol conflicts possible | Separate process, isolated address space |
| **Goroutine safety** | PAM callbacks happen on arbitrary threads; Go runtime thread management conflicts | Full Go runtime, no thread constraints |
| **Crash isolation** | Panic in Go code crashes sshd | Panic in Go code crashes only the child; PAM sees nonzero exit |
| **Cross-compilation** | Painful (musl vs glibc, architecture-specific headers) | Trivial with Go's built-in cross-compilation |
| **Testing** | Requires C test harness or complex mocking | Standard `go test`, subprocess tests |

The `pam_exec.so` approach trades a small amount of startup latency (forking a
process) for dramatically simpler builds, better crash isolation, and standard
Go testing.

## Package Structure and Responsibilities

```
linux-oidc-plugin/
  cmd/
    pam-oidc/            Entry point: config loading, dependency wiring, exit code
  internal/
    config/
      config.go          YAML loading, defaults, validation
      config_test.go     Unit tests for all config paths
    oidc/
      device.go          Device Authorization Grant client (RFC 8628)
      token.go           JWT parsing, JWKS fetching, ID token validation
      device_test.go     Tests with mock HTTP server
      token_test.go      Tests with mock JWKS + signed JWTs
    pam/
      handler.go         Authentication orchestrator (the main flow)
      io.go              Stdin/stdout/stderr abstraction, leveled logging
      handler_test.go    Tests with mock interfaces
      io_test.go         Tests for I/O and logging behavior
    user/
      mapper.go          Email-to-Linux-username mapping (email_prefix, static)
      mapper_test.go     Tests for both mapping strategies
  tests/
    integration/         Full flow tests with mock OIDC HTTP server
    e2e/                 Binary subprocess tests (build + exec)
```

### Package dependency graph

```
cmd/pam-oidc
  +---> internal/config
  +---> internal/oidc
  +---> internal/pam
  +---> internal/user

internal/pam
  +---> internal/config   (Config struct)
  +---> internal/oidc     (response types only)

internal/oidc
  (no internal dependencies)

internal/user
  (no internal dependencies)

internal/config
  (no internal dependencies)
```

All packages live under `internal/` to prevent external imports. The dependency
graph is intentionally shallow -- `pam` depends on `config` and `oidc` types,
but `oidc`, `user`, and `config` are independent of each other.

## Interface Design for Testability

The `pam.Handler` depends on three interfaces rather than concrete types:

```go
type DeviceFlowClient interface {
    RequestDeviceCode(ctx, clientID, clientSecret, scopes) (*oidc.DeviceAuthResponse, error)
    PollForToken(ctx, clientID, clientSecret, deviceCode, interval, timeout) (*oidc.TokenResponse, error)
}

type TokenValidatorInterface interface {
    ValidateIDToken(ctx, rawToken, expectedAudience) (*oidc.Claims, error)
}

type UserMapperInterface interface {
    MapEmailToUser(email) (string, error)
}
```

This design allows tests to:

- **Inject mock OIDC responses** without an HTTP server (unit tests for
  handler logic).
- **Simulate error conditions** -- network failures, invalid tokens, denied
  access -- by returning errors from mock implementations.
- **Run integration tests** with `httptest.Server` standing in for Google's
  endpoints.
- **Run end-to-end tests** by building the real binary and driving it via
  stdin/stdout/stderr pipes.

The `IOHandler` struct similarly abstracts `os.Stdin`, `os.Stdout`, and
`os.Stderr` behind `io.Reader` and `io.Writer` interfaces, making it possible
to capture and verify all I/O in tests without touching real file descriptors.
