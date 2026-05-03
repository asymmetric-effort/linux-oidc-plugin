# Linux PAM OIDC Plugin

<!-- Badges placeholder -->
<!-- [![Build Status](https://img.shields.io/github/actions/workflow/status/asymmetric-effort/linux-oidc-plugin/ci.yml?branch=main)](https://github.com/asymmetric-effort/linux-oidc-plugin/actions) -->
<!-- [![Coverage](https://img.shields.io/codecov/c/github/asymmetric-effort/linux-oidc-plugin)](https://codecov.io/gh/asymmetric-effort/linux-oidc-plugin) -->
<!-- [![Go Report Card](https://goreportcard.com/badge/github.com/asymmetric-effort/linux-oidc-plugin)](https://goreportcard.com/report/github.com/asymmetric-effort/linux-oidc-plugin) -->
<!-- [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt) -->

A Linux PAM module that authenticates users via Google OIDC using the OAuth 2.0
Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
Built as a standalone Go binary invoked by `pam_exec.so` -- no CGo, no shared
library compilation, no glibc version headaches.

## Overview

This plugin lets Linux servers authenticate SSH and console logins against
Google Workspace (or any Google Cloud identity) without passwords. Users see a
URL and a short code on their terminal, open a browser on any device, sign in
with their Google account, and the PAM session is granted.

### Why this exists

- **Passwordless authentication** -- eliminate shared passwords and local
  credential files on Linux servers.
- **Centralized identity** -- leverage your existing Google Workspace directory
  for Linux access control.
- **Device-flow friendly** -- works on headless servers with no browser, since
  authentication happens on a separate device.
- **Simple deployment** -- a single static binary plus a YAML config file.

## How It Works

```
  User at terminal             Linux Server (PAM)              Google OIDC
  ================             ==================              ===========

  1. ssh user@host ------>  pam_exec.so runs pam-oidc
                                    |
                            2. Request device code  ---------->  POST /device/code
                                    |                               |
                            3. Receive device_code  <----------  { device_code,
                               + user_code                         user_code,
                                    |                              verification_uri }
                            4. Display to user:
                               "Visit https://..."
                               "Enter code: ABCD-EFGH"
                                    |
  5. User opens browser,           |
     visits URL, enters     6. Poll for token  --------------->  POST /token
     code, signs in with           |                               |
     Google account                |   (authorization_pending)  <--|
                                   |          ...poll...           |
                                   |                               |
                            7. Receive ID token  <--------------  { id_token }
                                   |
                            8. Validate token:
                               - Verify JWT signature (JWKS)
                               - Check issuer = accounts.google.com
                               - Check audience = client_id
                               - Confirm email_verified = true
                                   |
                            9. Map email -> Linux username
                               - email_prefix: alice@example.com -> alice
                               - static: lookup in mapping table
                                   |
                           10. Compare mapped user == PAM_USER
                                   |
                           11. Exit 0 (success) or 1 (auth error)
```

## Features

- **OAuth 2.0 Device Authorization Grant** (RFC 8628) for headless server
  authentication
- **Google OIDC integration** with full JWT/JWKS validation
- **Flexible user mapping** -- `email_prefix` strips the domain automatically,
  or `static` provides an explicit email-to-username table
- **Domain allowlisting** -- restrict authentication to specific email domains
- **Configurable polling** -- tune interval and timeout for the device flow
- **Structured logging** to stderr with configurable log levels
  (debug, info, warn, error)
- **Pure Go** -- no CGo, cross-compiles cleanly for linux/amd64 and linux/arm64
- **Interface-driven design** -- all external dependencies are behind interfaces
  for straightforward testing

## Prerequisites

- **Go 1.23+** (for building from source)
- **Linux** with PAM support (`pam_exec.so` available)
- **Google Cloud project** with an OAuth 2.0 client ID configured for the
  device authorization flow
- **Network access** from the server to `oauth2.googleapis.com` and
  `www.googleapis.com`

## Quick Start

### 1. Build

```bash
git clone https://github.com/asymmetric-effort/linux-oidc-plugin.git
cd linux-oidc-plugin
make build
```

The binary is written to `./bin/pam-oidc`.

### 2. Configure

Create the configuration file:

```bash
sudo mkdir -p /etc/pam-oidc
sudo tee /etc/pam-oidc/config.yaml << 'EOF'
client_id: "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
allowed_domains:
  - "example.com"
user_mapping:
  type: email_prefix
EOF
sudo chmod 600 /etc/pam-oidc/config.yaml
```

### 3. Install

```bash
sudo cp ./bin/pam-oidc /usr/local/bin/pam-oidc
sudo chmod 755 /usr/local/bin/pam-oidc
```

### 4. Configure PAM

Add to `/etc/pam.d/sshd` (or the relevant PAM service):

```
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

### 5. Test

Run the binary directly to verify the flow works before enabling it in PAM:

```bash
PAM_USER=your_username /usr/local/bin/pam-oidc
```

See the [Installation Guide](docs/installation.md) for detailed instructions.

## Configuration Reference

All configuration is in YAML format. The default path is
`/etc/pam-oidc/config.yaml`. Override with the `PAM_OIDC_CONFIG` environment
variable.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_id` | string | *(required)* | Google OAuth 2.0 client ID |
| `client_secret` | string | `""` | Client secret (optional for device flow) |
| `scopes` | list | `["openid", "email"]` | OAuth scopes to request |
| `allowed_domains` | list | *(required)* | Email domains permitted to authenticate |
| `user_mapping.type` | string | `"email_prefix"` | Mapping strategy: `email_prefix` or `static` |
| `user_mapping.mappings` | map | `{}` | Email-to-username map (required when type is `static`) |
| `poll_interval_seconds` | int | `5` | Seconds between token polling requests |
| `poll_timeout_seconds` | int | `300` | Maximum seconds to wait for user to authenticate |
| `log_level` | string | `"info"` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `device_endpoint` | string | `https://oauth2.googleapis.com/device/code` | Device authorization endpoint (override for testing) |
| `token_endpoint` | string | `https://oauth2.googleapis.com/token` | Token endpoint (override for testing) |
| `jwks_endpoint` | string | `https://www.googleapis.com/oauth2/v3/certs` | JWKS endpoint (override for testing) |

See [docs/configuration.md](docs/configuration.md) for complete details and
example configurations.

## PAM Configuration

Add the following line to the appropriate file in `/etc/pam.d/`:

```
# /etc/pam.d/sshd
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

Key options for `pam_exec.so`:

- `required` -- authentication must succeed (use `sufficient` to fall back to
  other methods)
- `expose_authtok` -- makes the PAM token available (needed for stdin
  communication)

For SSH, also ensure `ChallengeResponseAuthentication yes` (or
`KbdInteractiveAuthentication yes` on newer OpenSSH) is set in
`/etc/ssh/sshd_config`.

## Security Considerations

- **Config file permissions** -- `/etc/pam-oidc/config.yaml` should be readable
  only by root (`chmod 600`). It may contain a client secret.
- **Token validation** -- ID tokens are validated against Google's JWKS
  endpoint. The plugin verifies the JWT signature, issuer, audience, expiration,
  and `email_verified` claim.
- **No token storage** -- tokens are validated in memory and never written to
  disk.
- **Domain restrictions** -- the `allowed_domains` field restricts which Google
  accounts may authenticate. Always set this to your organization's domain(s).
- **User mapping** -- the mapped Linux username must match the PAM-supplied
  `PAM_USER` value exactly. A user cannot authenticate as a different account.
- **Network security** -- all communication with Google endpoints uses HTTPS.
  Ensure your server can reach `oauth2.googleapis.com` and
  `www.googleapis.com` on port 443.
- **Audit logging** -- all authentication attempts are logged to stderr (which
  PAM typically routes to syslog/journald). Set `log_level: info` or `debug`
  for full audit trails.

## Testing

```bash
# Run all tests (unit + integration + e2e) with race detector
make test

# Run linting (go vet + govulncheck)
make lint

# Generate coverage report
go tool cover -html=coverage.out

# Clean build artifacts
make clean
```

The project targets 98%+ test coverage. Tests use `httptest.Server` for mock
OIDC endpoints and subprocess execution for end-to-end tests.

## Contributing

Contributions are welcome. Please see [CONTRIBUTORS.md](CONTRIBUTORS.md) for
guidelines.

1. Fork the repository
2. Create a feature branch
3. Ensure `make test` and `make lint` pass
4. Open a Pull Request

## License

This project is licensed under the MIT License. See [LICENSE.txt](LICENSE.txt)
for details.
