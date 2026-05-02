# Troubleshooting

## Quick Diagnostics

Before diving into specific issues, run these checks:

```bash
# 1. Verify the binary exists and is executable
ls -la /usr/local/bin/pam-oidc

# 2. Verify the config file is readable
sudo cat /etc/pam-oidc/config.yaml

# 3. Test the binary directly (outside of PAM)
PAM_USER=your_username /usr/local/bin/pam-oidc

# 4. Check system logs
sudo journalctl -u sshd --since "5 minutes ago"
```

## Debug Logging

The most effective troubleshooting step is enabling debug logging. Edit
`/etc/pam-oidc/config.yaml`:

```yaml
log_level: debug
```

Log output is written to stderr, which PAM routes to the system log. All log
messages are prefixed with their level:

```
[DEBUG] starting OIDC authentication
[INFO] authenticating user: alice
[DEBUG] device code issued, expires in 1800 seconds
[INFO] token received, validating...
[INFO] token validated for email: alice@example.com
[INFO] authentication successful for user: alice
```

View logs in real time:

```bash
# systemd/journald
sudo journalctl -u sshd -f

# Traditional syslog (Debian/Ubuntu)
sudo tail -f /var/log/auth.log

# Traditional syslog (RHEL/CentOS)
sudo tail -f /var/log/secure
```

## Testing the Auth Flow Manually

Run the binary directly to test the full flow without PAM involvement:

```bash
# Basic test
PAM_USER=your_username /usr/local/bin/pam-oidc

# With debug output visible on terminal
PAM_USER=your_username /usr/local/bin/pam-oidc 2>&1

# With a custom config file
PAM_OIDC_CONFIG=/tmp/test-config.yaml PAM_USER=your_username /usr/local/bin/pam-oidc 2>&1
```

Check the exit code:

```bash
PAM_USER=your_username /usr/local/bin/pam-oidc 2>/dev/null
echo $?
# 0 = success, 1 = auth error, 2 = system error
```

## Common Errors and Solutions

### Config File Not Found

**Symptom**: Exit code 2. Log message:
```
[ERROR] failed to load config: reading config file /etc/pam-oidc/config.yaml: open /etc/pam-oidc/config.yaml: no such file or directory
```

**Solution**: Create the config file or set `PAM_OIDC_CONFIG` to the correct
path.

```bash
sudo mkdir -p /etc/pam-oidc
sudo vim /etc/pam-oidc/config.yaml
```

---

### Config Validation Failure

**Symptom**: Exit code 2. Log messages such as:
```
[ERROR] failed to load config: client_id is required
[ERROR] failed to load config: at least one allowed_domain is required
[ERROR] failed to load config: user_mapping.type must be 'email_prefix' or 'static', got "unknown"
```

**Solution**: Fix the config file. Required fields:

```yaml
client_id: "your-client-id.apps.googleusercontent.com"
allowed_domains:
  - "your-domain.com"
```

---

### Permission Denied on Config File

**Symptom**: Exit code 2. Log message:
```
[ERROR] failed to load config: reading config file /etc/pam-oidc/config.yaml: open /etc/pam-oidc/config.yaml: permission denied
```

**Solution**: The binary runs as the user calling PAM (typically root for
sshd). Ensure the config is readable:

```bash
sudo chown root:root /etc/pam-oidc/config.yaml
sudo chmod 600 /etc/pam-oidc/config.yaml
```

---

### Device Code Request Failed

**Symptom**: Exit code 2. Log message:
```
[ERROR] failed to request device code: device code request failed: invalid_client: The OAuth client was not found.
```

**Causes and solutions**:

- **Invalid client_id**: Verify the client ID in the Google Cloud Console under
  **APIs & Services > Credentials**.
- **Wrong application type**: The client must be "TVs and Limited Input devices"
  or "Desktop app". Web application client IDs do not support the device flow.
- **API not enabled**: Ensure the project has not disabled the OAuth endpoints.

---

### Network Connection Failures

**Symptom**: Exit code 2. Log messages such as:
```
[ERROR] failed to request device code: requesting device code: Post "https://oauth2.googleapis.com/device/code": dial tcp: lookup oauth2.googleapis.com: no such host
[ERROR] failed to request device code: requesting device code: Post "https://oauth2.googleapis.com/device/code": context deadline exceeded
```

**Solutions**:

1. **DNS resolution**: Verify the server can resolve Google hostnames:
   ```bash
   nslookup oauth2.googleapis.com
   nslookup www.googleapis.com
   ```

2. **Firewall**: Ensure outbound HTTPS (port 443) is allowed:
   ```bash
   curl -v https://oauth2.googleapis.com/device/code
   ```

3. **Proxy**: If the server uses an HTTP proxy, set the standard environment
   variables. Note that these must be set in the environment where `pam-oidc`
   runs (i.e., the sshd process environment):
   ```bash
   # In /etc/environment or the sshd systemd override
   HTTPS_PROXY=http://proxy.example.com:8080
   HTTP_PROXY=http://proxy.example.com:8080
   NO_PROXY=localhost,127.0.0.1
   ```

   For systemd-managed sshd:
   ```bash
   sudo systemctl edit sshd
   ```
   ```ini
   [Service]
   Environment="HTTPS_PROXY=http://proxy.example.com:8080"
   ```

---

### Polling Timed Out

**Symptom**: Exit code 1. Log message:
```
[ERROR] failed to obtain token: polling timed out after 300 seconds
```

**Causes and solutions**:

- The user did not complete the browser-based sign-in within the timeout
  period. Increase `poll_timeout_seconds` in the config:
  ```yaml
  poll_timeout_seconds: 600
  ```
- The user may not have seen the verification URL. Check that stdout from
  `pam_exec.so` reaches the user's terminal.

---

### Access Denied by User

**Symptom**: Exit code 1. Log message:
```
[ERROR] failed to obtain token: access denied by user
```

**Solution**: The user clicked "Deny" on the Google consent screen. They need
to retry and click "Allow".

---

### Device Code Expired

**Symptom**: Exit code 1. Log message:
```
[ERROR] failed to obtain token: device code expired
```

**Solution**: The device code has a limited lifetime (typically 30 minutes).
The user must start the flow again and complete it within the time limit.

---

### Token Validation Failures

**Symptom**: Exit code 1. Various log messages.

#### Invalid Issuer

```
[ERROR] token validation failed: invalid issuer: "https://some-other-issuer.com"
```

The plugin only accepts tokens issued by `accounts.google.com` or
`https://accounts.google.com`. If you see a different issuer, the token is not
from Google. Verify you are not pointing the endpoints at a non-Google provider.

#### Invalid Audience

```
[ERROR] token validation failed: invalid audience: expected "YOUR_CLIENT_ID" got "DIFFERENT_ID"
```

The `aud` claim in the token does not match the `client_id` in the config.
Ensure the `client_id` in the config matches the OAuth client used to initiate
the flow.

#### Email Not Verified

```
[ERROR] token validation failed: email not verified
```

The Google account's email is not verified. This is rare for Google Workspace
accounts. The user needs to verify their email in their Google account settings.

#### JWKS Fetch Failed

```
[ERROR] token validation failed: fetching JWKS for validation: fetching JWKS: Get "https://www.googleapis.com/oauth2/v3/certs": dial tcp: ...
```

The server cannot reach Google's JWKS endpoint. See the
[Network Connection Failures](#network-connection-failures) section.

#### Expired Token

```
[ERROR] token validation failed: parsing/validating token: token has invalid claims: token is expired
```

The ID token has expired. This can happen if there is significant clock skew
between the server and Google's servers. Fix with NTP:

```bash
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd
timedatectl status
```

---

### User Mapping Issues

#### Domain Not Allowed

**Symptom**: Exit code 1. Log message:
```
[ERROR] user mapping failed: domain "personal.gmail.com" is not in allowed domains
```

**Solution**: The user authenticated with a Google account whose domain is not
in the `allowed_domains` list. Add the domain or use a different account:

```yaml
allowed_domains:
  - "example.com"
  - "other-domain.com"
```

#### No Static Mapping Found

**Symptom**: Exit code 1. Log message:
```
[ERROR] user mapping failed: no mapping found for email "newuser@example.com"
```

**Solution**: When using `static` mapping, every authorized email must have
an entry:

```yaml
user_mapping:
  type: static
  mappings:
    "newuser@example.com": "newuser"
```

#### Username Mismatch

**Symptom**: Exit code 1. Log message:
```
[ERROR] username mismatch: PAM user "bob" != mapped user "robert"
```

**Cause**: The Linux username (from `PAM_USER`) does not match the username
derived from the email. For example, the user is logging in as `bob` but their
email `robert@example.com` maps to `robert`.

**Solutions**:

- If using `email_prefix`: the Linux username must match the email prefix
  exactly. Rename the Linux user or use `static` mapping.
- If using `static`: update the mapping to point the email to the correct
  Linux username:
  ```yaml
  user_mapping:
    type: static
    mappings:
      "robert@example.com": "bob"
  ```

---

### PAM Configuration Issues

#### pam-oidc Binary Not Found

**Symptom**: PAM logs:
```
pam_exec(sshd:auth): failed to execute /usr/local/bin/pam-oidc: No such file or directory
```

**Solution**: Install the binary to the correct path:

```bash
sudo cp ./bin/pam-oidc /usr/local/bin/pam-oidc
sudo chmod 755 /usr/local/bin/pam-oidc
```

#### pam-oidc Binary Not Executable

**Symptom**: PAM logs:
```
pam_exec(sshd:auth): failed to execute /usr/local/bin/pam-oidc: Permission denied
```

**Solution**:

```bash
sudo chmod 755 /usr/local/bin/pam-oidc
```

#### No Output Shown to User

**Symptom**: The user does not see the verification URL when logging in via
SSH.

**Solutions**:

1. Ensure `expose_authtok` is in the PAM config line:
   ```
   auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
   ```

2. Ensure SSH is configured for keyboard-interactive authentication:
   ```
   # /etc/ssh/sshd_config
   KbdInteractiveAuthentication yes
   UsePAM yes
   ```

3. Restart sshd:
   ```bash
   sudo systemctl restart sshd
   ```

#### Locked Out of System

If a PAM misconfiguration locks you out:

1. **Boot into single-user mode** or use a recovery console.
2. **Use an existing root session** if one is still open (always keep one open
   when testing PAM changes).
3. **Mount the filesystem** and edit `/etc/pam.d/sshd` to remove or comment
   out the `pam_exec.so` line.
4. Reboot and reconfigure.

**Prevention**: Always keep a root SSH session or console session open while
testing PAM changes.

---

### SELinux Denials

**Symptom**: Binary works when run manually but fails under PAM. SELinux
audit log shows denials.

**Diagnosis**:

```bash
sudo ausearch -m avc -ts recent | grep pam-oidc
```

**Solution**:

```bash
sudo audit2allow -a -M pam-oidc-policy
sudo semodule -i pam-oidc-policy.pp
```

Or set the appropriate context:

```bash
sudo chcon -t bin_t /usr/local/bin/pam-oidc
sudo restorecon /usr/local/bin/pam-oidc
```

## Log Level Reference

| Level | Output |
|-------|--------|
| `debug` | All messages: debug, info, warn, error |
| `info` | Info, warn, and error messages (default) |
| `warn` | Warn and error messages only |
| `error` | Error messages only |

All log output goes to stderr with the format:

```
[LEVEL] message text
```

PAM typically captures stderr and routes it to the system log (syslog or
journald).

## Getting Help

If the troubleshooting steps above do not resolve your issue:

1. Enable `log_level: debug` and capture the full log output.
2. Test the binary manually with `PAM_USER=... /usr/local/bin/pam-oidc 2>&1`
   and note the exit code.
3. Check the Google Cloud Console for any OAuth-related errors or rate limits.
4. Open an issue with the debug logs (redact the client ID and any tokens).
