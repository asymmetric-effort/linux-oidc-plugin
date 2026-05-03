# Installation Guide

## Prerequisites

- **Linux** with PAM support (Debian/Ubuntu, RHEL/CentOS, Fedora, Arch, etc.)
- **Go 1.23+** (for building from source)
- **`pam_exec.so`** -- included in the `libpam-modules` package on
  Debian/Ubuntu or `pam` on RHEL/Fedora. Virtually all Linux distributions
  ship it by default.
- **Google Cloud OAuth 2.0 client ID** -- see
  [Configuration: Google Cloud Console Setup](configuration.md#google-cloud-console-setup)
- **Network access** from the server to:
  - `oauth2.googleapis.com` (port 443)
  - `www.googleapis.com` (port 443)

## Building from Source

### Clone and Build

```bash
git clone https://github.com/asymmetric-effort/linux-oidc-plugin.git
cd linux-oidc-plugin
make build
```

The binary is written to `./bin/pam-oidc`.

### Cross-Compilation

Build for a different architecture:

```bash
# ARM64 (e.g., AWS Graviton, Raspberry Pi 4)
GOOS=linux GOARCH=arm64 go build -o bin/pam-oidc-arm64 ./cmd/pam-oidc/

# AMD64
GOOS=linux GOARCH=amd64 go build -o bin/pam-oidc-amd64 ./cmd/pam-oidc/
```

Or use the release target which builds both:

```bash
make release
```

### Verify the Build

```bash
# Run tests first
make test

# Check the binary
file ./bin/pam-oidc
./bin/pam-oidc --help  # or just run it to see behavior
```

## Installing the Binary

Copy the binary to a system-wide location:

```bash
sudo cp ./bin/pam-oidc /usr/local/bin/pam-oidc
sudo chown root:root /usr/local/bin/pam-oidc
sudo chmod 755 /usr/local/bin/pam-oidc
```

Verify it is accessible:

```bash
which pam-oidc
/usr/local/bin/pam-oidc
```

## Creating the Config File

### Create the Directory

```bash
sudo mkdir -p /etc/pam-oidc
```

### Write the Config

```bash
sudo tee /etc/pam-oidc/config.yaml << 'EOF'
client_id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
allowed_domains:
  - "your-domain.com"
user_mapping:
  type: email_prefix
log_level: info
EOF
```

### Secure the Config

The config file may contain a client secret. Restrict permissions:

```bash
sudo chown root:root /etc/pam-oidc/config.yaml
sudo chmod 600 /etc/pam-oidc/config.yaml
```

See [Configuration Reference](configuration.md) for all available fields.

## PAM Configuration

### SSH Authentication

Edit `/etc/pam.d/sshd` and add the `pam_exec.so` line. Placement depends on
your desired behavior.

#### Option A: OIDC Required (replaces password auth)

Add near the top of the `auth` section:

```
# /etc/pam.d/sshd
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

This requires OIDC authentication to succeed. If it fails, the login is
denied regardless of other auth methods.

#### Option B: OIDC Sufficient (with password fallback)

```
# /etc/pam.d/sshd
auth sufficient pam_exec.so expose_authtok /usr/local/bin/pam-oidc
auth required pam_unix.so
```

If OIDC succeeds, the user is authenticated. If it fails, PAM falls through
to standard password authentication.

#### Option C: OIDC as Additional Factor

```
# /etc/pam.d/sshd
auth required pam_unix.so
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

Both password and OIDC must succeed (two-factor authentication).

### Console Login

Edit `/etc/pam.d/login`:

```
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

### Sudo

Edit `/etc/pam.d/sudo`:

```
auth sufficient pam_exec.so expose_authtok /usr/local/bin/pam-oidc
auth required pam_unix.so
```

### SSH Daemon Configuration

For SSH, ensure `sshd_config` allows keyboard-interactive authentication:

```
# /etc/ssh/sshd_config
KbdInteractiveAuthentication yes
# Older OpenSSH versions use:
# ChallengeResponseAuthentication yes
UsePAM yes
```

Restart sshd after changes:

```bash
sudo systemctl restart sshd
```

## Testing the Installation

### Step 1: Test the Binary Directly

Before enabling PAM integration, verify the binary works:

```bash
# Set PAM_USER to simulate PAM providing the username
PAM_USER=your_username /usr/local/bin/pam-oidc
```

You should see:

```
To sign in, open your browser and visit:
  https://www.google.com/device

Enter the code: ABCD-EFGH
```

Open the URL in a browser, enter the code, and sign in with your Google
account. If everything is configured correctly, you will see:

```
Authentication successful!
```

And the binary will exit with code 0:

```bash
echo $?
0
```

### Step 2: Test with Debug Logging

Temporarily set `log_level: debug` in the config to see detailed output on
stderr:

```bash
PAM_USER=your_username /usr/local/bin/pam-oidc 2>&1
```

### Step 3: Test PAM Integration

Keep an existing SSH session open as a safety net, then test from a new
terminal:

```bash
ssh your_username@localhost
```

**Important**: Always keep a root/sudo session open when testing PAM changes.
A misconfigured PAM stack can lock you out of the system.

### Step 4: Check Logs

PAM logs are typically written to syslog or journald:

```bash
# systemd/journald
sudo journalctl -u sshd -f

# Traditional syslog
sudo tail -f /var/log/auth.log
```

## Systemd Integration Notes

### Sshd and PAM

The `sshd` service is managed by systemd on most modern distributions. When
`pam_exec.so` invokes the `pam-oidc` binary, it runs as a child process of
sshd with the same user and group. No separate systemd unit is needed for the
plugin itself.

### Resource Limits

If you observe issues with the plugin under heavy load, you can adjust sshd's
resource limits in its systemd override:

```bash
sudo systemctl edit sshd
```

```ini
[Service]
# Increase open file limit if many concurrent logins
LimitNOFILE=65536
# Increase process limit
LimitNPROC=4096
```

### Timeouts

The plugin has its own timeout (`poll_timeout_seconds`, default 300 seconds).
Ensure that any SSH or PAM timeouts are at least as long:

```
# /etc/ssh/sshd_config
LoginGraceTime 600
```

### SELinux Considerations

On RHEL/CentOS/Fedora with SELinux enforcing, you may need to allow `pam_exec.so`
to run the binary:

```bash
# Check for denials
sudo ausearch -m avc -ts recent

# If pam-oidc is blocked, create a policy module
sudo audit2allow -a -M pam-oidc
sudo semodule -i pam-oidc.pp
```

Alternatively, set the correct SELinux context on the binary:

```bash
sudo chcon -t bin_t /usr/local/bin/pam-oidc
```

## Multi-Factor Authentication (MFA) Considerations

### OIDC as Single Factor

When used alone, this plugin provides single-factor authentication via Google
identity. Google's own login process may include MFA (Google 2-Step
Verification), so the effective security depends on your Google Workspace
policies.

### OIDC + Password (Two Factors)

To require both a password and OIDC:

```
# /etc/pam.d/sshd
auth required pam_unix.so
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
```

The user must first enter their Linux password, then complete the OIDC device
flow.

### OIDC + Hardware Key

Combine with `pam_u2f.so` or similar for OIDC + hardware key:

```
# /etc/pam.d/sshd
auth required pam_exec.so expose_authtok /usr/local/bin/pam-oidc
auth required pam_u2f.so
```

### Google Workspace MFA Policies

For the strongest security posture, enforce MFA at the Google Workspace level:

1. Go to **Google Admin Console > Security > 2-Step Verification**.
2. Set enforcement to **On** for the relevant organizational units.
3. This ensures that every OIDC authentication through the device flow
   requires the user to complete Google's own MFA challenge.

With Google Workspace MFA enforced, the plugin effectively provides MFA even
when used as the sole PAM authentication method, because the Google login step
requires a second factor.

## Uninstalling

```bash
# Remove the binary
sudo rm /usr/local/bin/pam-oidc

# Remove the config
sudo rm -rf /etc/pam-oidc

# Remove PAM configuration (edit the relevant /etc/pam.d/ file)
# Remove the pam_exec.so line referencing pam-oidc

# Restart sshd if you modified its PAM config
sudo systemctl restart sshd
```
