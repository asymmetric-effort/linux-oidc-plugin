# Configuration Reference

## Config File Location

The default configuration file path is:

```
/etc/pam-oidc/config.yaml
```

Override this by setting the `PAM_OIDC_CONFIG` environment variable:

```bash
PAM_OIDC_CONFIG=/path/to/custom/config.yaml /usr/local/bin/pam-oidc
```

The config file is YAML format, parsed with `gopkg.in/yaml.v3`.

## Field Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `client_id` | string | Google OAuth 2.0 client ID. Obtained from the Google Cloud Console. |
| `allowed_domains` | list of strings | Email domains permitted to authenticate. At least one is required. |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_secret` | string | `""` | OAuth client secret. Optional for the device flow, but some configurations require it. |
| `scopes` | list of strings | `["openid", "email"]` | OAuth scopes to request. Must include `openid` and `email` for OIDC to work. |
| `user_mapping.type` | string | `"email_prefix"` | How to map Google email to Linux username. Options: `email_prefix`, `static`. |
| `user_mapping.mappings` | map of string to string | `{}` | Explicit email-to-username mappings. Required when `user_mapping.type` is `static`. |
| `poll_interval_seconds` | int | `5` | Seconds between token endpoint polling requests during device flow. Minimum: 1. |
| `poll_timeout_seconds` | int | `300` | Maximum seconds to wait for the user to complete authentication. Minimum: 1. |
| `log_level` | string | `"info"` | Log verbosity. One of: `debug`, `info`, `warn`, `error`. |

### Endpoint Overrides (Testing)

These fields override the default Google OIDC endpoints. They are intended for
testing with mock servers and should not be set in production.

| Field | Type | Default |
|-------|------|---------|
| `device_endpoint` | string | `https://oauth2.googleapis.com/device/code` |
| `token_endpoint` | string | `https://oauth2.googleapis.com/token` |
| `jwks_endpoint` | string | `https://www.googleapis.com/oauth2/v3/certs` |

## Default Values Summary

| Field | Default Value |
|-------|---------------|
| `client_secret` | `""` (empty) |
| `scopes` | `["openid", "email"]` |
| `user_mapping.type` | `"email_prefix"` |
| `poll_interval_seconds` | `5` |
| `poll_timeout_seconds` | `300` |
| `log_level` | `"info"` |
| `device_endpoint` | `https://oauth2.googleapis.com/device/code` |
| `token_endpoint` | `https://oauth2.googleapis.com/token` |
| `jwks_endpoint` | `https://www.googleapis.com/oauth2/v3/certs` |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `PAM_OIDC_CONFIG` | Override the config file path. Takes precedence over the default `/etc/pam-oidc/config.yaml` and any path passed programmatically. |
| `PAM_USER` | Set by PAM (via `pam_exec.so`). Contains the username of the user being authenticated. The plugin reads this first; if unset, it falls back to reading from stdin. |

## Validation Rules

The config loader enforces these rules at startup. If any rule is violated, the
plugin exits with code 2 (system error) and logs the specific validation
failure.

- `client_id` must be non-empty.
- `allowed_domains` must contain at least one entry.
- `user_mapping.type` must be `"email_prefix"` or `"static"`.
- When `user_mapping.type` is `"static"`, `user_mapping.mappings` must be
  non-empty.
- `log_level` must be one of: `debug`, `info`, `warn`, `error`.
- `poll_interval_seconds` must be >= 1.
- `poll_timeout_seconds` must be >= 1.

## Example Configurations

### Minimal Configuration

The simplest working config. Uses `email_prefix` mapping, so
`alice@example.com` authenticates as Linux user `alice`.

```yaml
client_id: "123456789.apps.googleusercontent.com"
allowed_domains:
  - "example.com"
```

### Email Prefix Mapping (explicit)

Equivalent to the minimal config but with all defaults spelled out.

```yaml
client_id: "123456789.apps.googleusercontent.com"
client_secret: ""
scopes:
  - openid
  - email
allowed_domains:
  - "example.com"
user_mapping:
  type: email_prefix
poll_interval_seconds: 5
poll_timeout_seconds: 300
log_level: info
```

### Static Mapping

Map specific Google accounts to specific Linux usernames. Useful when email
prefixes do not match Linux usernames.

```yaml
client_id: "123456789.apps.googleusercontent.com"
allowed_domains:
  - "example.com"
  - "contractor.io"
user_mapping:
  type: static
  mappings:
    "alice.johnson@example.com": "ajohnson"
    "bob.smith@example.com": "bsmith"
    "carol@contractor.io": "carol_ext"
log_level: info
```

### Multiple Domains

Allow authentication from multiple email domains.

```yaml
client_id: "123456789.apps.googleusercontent.com"
allowed_domains:
  - "example.com"
  - "example.org"
  - "subsidiary.example.com"
user_mapping:
  type: email_prefix
```

### Debug Logging

Enable verbose logging to troubleshoot authentication issues.

```yaml
client_id: "123456789.apps.googleusercontent.com"
allowed_domains:
  - "example.com"
user_mapping:
  type: email_prefix
log_level: debug
poll_interval_seconds: 5
poll_timeout_seconds: 600
```

### Custom Endpoints (Testing)

Point the plugin at a local mock server for development and testing.

```yaml
client_id: "test-client-id"
allowed_domains:
  - "test.example.com"
user_mapping:
  type: email_prefix
device_endpoint: "http://localhost:8080/device/code"
token_endpoint: "http://localhost:8080/token"
jwks_endpoint: "http://localhost:8080/.well-known/jwks.json"
log_level: debug
```

## Google Cloud Console Setup

Follow these steps to create an OAuth 2.0 client ID configured for the device
authorization flow.

### Step 1: Create or Select a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Select an existing project or click **New Project** to create one.
3. Note the project ID.

### Step 2: Enable Required APIs

1. Navigate to **APIs & Services > Library**.
2. Search for and enable **Google Identity** (or ensure the default OAuth
   endpoints are accessible -- they are enabled by default for most projects).

### Step 3: Configure the OAuth Consent Screen

1. Navigate to **APIs & Services > OAuth consent screen**.
2. Choose **Internal** (for Google Workspace organizations) or **External**
   (for testing).
3. Fill in the required fields:
   - **App name**: e.g., "Linux PAM OIDC"
   - **User support email**: your admin email
   - **Developer contact**: your email
4. Under **Scopes**, add:
   - `openid`
   - `email`
5. Save.

### Step 4: Create OAuth Client ID

1. Navigate to **APIs & Services > Credentials**.
2. Click **Create Credentials > OAuth client ID**.
3. For **Application type**, select one of:
   - **TVs and Limited Input devices** (preferred -- purpose-built for device
     flow)
   - **Desktop app** (also works for device flow)
4. Give it a name, e.g., "pam-oidc-plugin".
5. Click **Create**.
6. Copy the **Client ID** (and **Client Secret** if provided).

### Step 5: Verify Device Flow Access

The device authorization endpoint (`https://oauth2.googleapis.com/device/code`)
is available for client IDs of type "TVs and Limited Input devices" and
"Desktop app". No additional configuration is needed.

### Step 6: Configure the Plugin

Place the client ID in your config file:

```yaml
client_id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
# client_secret: "YOUR_CLIENT_SECRET"  # if provided
allowed_domains:
  - "your-domain.com"
```

### Notes on Client Secrets

- For **TVs and Limited Input devices** type, Google may or may not issue a
  client secret. The device flow works without one.
- For **Desktop app** type, a client secret is issued but is not considered
  truly secret (it is embedded in distributed software). You may include it
  in the config for compatibility.
- The `client_secret` field in the config is optional. If set, it is sent with
  both the device code request and token polling requests.
