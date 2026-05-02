package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

const validMinimalConfig = `
client_id: "test-client-id"
allowed_domains:
  - example.com
`

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, validMinimalConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "test-client-id")
	}
	if len(cfg.AllowedDomains) != 1 || cfg.AllowedDomains[0] != "example.com" {
		t.Errorf("AllowedDomains = %v, want [example.com]", cfg.AllowedDomains)
	}
}

func TestLoadWithEnvOverride(t *testing.T) {
	path := writeConfig(t, validMinimalConfig)
	t.Setenv(EnvConfigPath, path)

	cfg, err := Load("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "test-client-id")
	}
}

func TestLoadEmptyPathUsesDefault(t *testing.T) {
	// With no env var and empty path, Load uses DefaultConfigPath which won't exist
	t.Setenv(EnvConfigPath, "")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for default config path, got nil")
	}
	if !strings.Contains(err.Error(), DefaultConfigPath) {
		t.Errorf("error should mention default path %q, got: %v", DefaultConfigPath, err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Setenv(EnvConfigPath, "")
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading config file") {
		t.Errorf("error should mention reading config file, got: %v", err)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeConfig(t, "{{{{not valid yaml::::")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing config file") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestValidateEmptyClientID(t *testing.T) {
	path := writeConfig(t, `
client_id: ""
allowed_domains:
  - example.com
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty client_id")
	}
	if !strings.Contains(err.Error(), "client_id is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMissingAllowedDomains(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains: []
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing allowed_domains")
	}
	if !strings.Contains(err.Error(), "at least one allowed_domain is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateInvalidUserMappingType(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
user_mapping:
  type: "bogus"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid user_mapping.type")
	}
	if !strings.Contains(err.Error(), "user_mapping.type must be") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateStaticMappingWithoutMappings(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
user_mapping:
  type: "static"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for static mapping without mappings")
	}
	if !strings.Contains(err.Error(), "user_mapping.mappings is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateStaticMappingWithMappings(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
user_mapping:
  type: "static"
  mappings:
    user@example.com: "localuser"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UserMapping.Type != "static" {
		t.Errorf("UserMapping.Type = %q, want %q", cfg.UserMapping.Type, "static")
	}
	if cfg.UserMapping.Mappings["user@example.com"] != "localuser" {
		t.Errorf("mapping not preserved")
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
log_level: "trace"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid log_level")
	}
	if !strings.Contains(err.Error(), "log_level must be one of") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateAllValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
log_level: "`+level+`"
`)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("unexpected error for log_level %q: %v", level, err)
			}
			if cfg.LogLevel != level {
				t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
			}
		})
	}
}

func TestDefaultsApplied(t *testing.T) {
	path := writeConfig(t, validMinimalConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scopes default
	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "openid" || cfg.Scopes[1] != "email" {
		t.Errorf("Scopes = %v, want [openid email]", cfg.Scopes)
	}

	// Poll interval default
	if cfg.PollIntervalSeconds != DefaultPollInterval {
		t.Errorf("PollIntervalSeconds = %d, want %d", cfg.PollIntervalSeconds, DefaultPollInterval)
	}

	// Poll timeout default
	if cfg.PollTimeoutSeconds != DefaultPollTimeout {
		t.Errorf("PollTimeoutSeconds = %d, want %d", cfg.PollTimeoutSeconds, DefaultPollTimeout)
	}

	// Log level default
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}

	// User mapping type default
	if cfg.UserMapping.Type != "email_prefix" {
		t.Errorf("UserMapping.Type = %q, want %q", cfg.UserMapping.Type, "email_prefix")
	}

	// Endpoint defaults
	if cfg.DeviceEndpoint != "https://oauth2.googleapis.com/device/code" {
		t.Errorf("DeviceEndpoint = %q, want default", cfg.DeviceEndpoint)
	}
	if cfg.TokenEndpoint != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenEndpoint = %q, want default", cfg.TokenEndpoint)
	}
	if cfg.JWKSEndpoint != "https://www.googleapis.com/oauth2/v3/certs" {
		t.Errorf("JWKSEndpoint = %q, want default", cfg.JWKSEndpoint)
	}
}

func TestCustomEndpointsPreserved(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
device_endpoint: "https://custom.example.com/device"
token_endpoint: "https://custom.example.com/token"
jwks_endpoint: "https://custom.example.com/jwks"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeviceEndpoint != "https://custom.example.com/device" {
		t.Errorf("DeviceEndpoint = %q, want custom", cfg.DeviceEndpoint)
	}
	if cfg.TokenEndpoint != "https://custom.example.com/token" {
		t.Errorf("TokenEndpoint = %q, want custom", cfg.TokenEndpoint)
	}
	if cfg.JWKSEndpoint != "https://custom.example.com/jwks" {
		t.Errorf("JWKSEndpoint = %q, want custom", cfg.JWKSEndpoint)
	}
}

func TestCustomScopesPreserved(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
scopes:
  - openid
  - email
  - profile
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Scopes) != 3 || cfg.Scopes[2] != "profile" {
		t.Errorf("Scopes = %v, want [openid email profile]", cfg.Scopes)
	}
}

func TestCustomPollValues(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
allowed_domains:
  - example.com
poll_interval_seconds: 10
poll_timeout_seconds: 600
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PollIntervalSeconds != 10 {
		t.Errorf("PollIntervalSeconds = %d, want 10", cfg.PollIntervalSeconds)
	}
	if cfg.PollTimeoutSeconds != 600 {
		t.Errorf("PollTimeoutSeconds = %d, want 600", cfg.PollTimeoutSeconds)
	}
}

func TestValidatePollIntervalLessThanOne(t *testing.T) {
	cfg := &Config{
		ClientID:            "test",
		AllowedDomains:      []string{"example.com"},
		UserMapping:         UserMapping{Type: "email_prefix"},
		LogLevel:            "info",
		PollIntervalSeconds: 0,
		PollTimeoutSeconds:  300,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for poll_interval_seconds < 1")
	}
	if !strings.Contains(err.Error(), "poll_interval_seconds must be >= 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidatePollTimeoutLessThanOne(t *testing.T) {
	cfg := &Config{
		ClientID:            "test",
		AllowedDomains:      []string{"example.com"},
		UserMapping:         UserMapping{Type: "email_prefix"},
		LogLevel:            "info",
		PollIntervalSeconds: 5,
		PollTimeoutSeconds:  0,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for poll_timeout_seconds < 1")
	}
	if !strings.Contains(err.Error(), "poll_timeout_seconds must be >= 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateNegativePollInterval(t *testing.T) {
	cfg := &Config{
		ClientID:            "test",
		AllowedDomains:      []string{"example.com"},
		UserMapping:         UserMapping{Type: "email_prefix"},
		LogLevel:            "info",
		PollIntervalSeconds: -1,
		PollTimeoutSeconds:  300,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative poll_interval_seconds")
	}
	if !strings.Contains(err.Error(), "poll_interval_seconds must be >= 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateNegativePollTimeout(t *testing.T) {
	cfg := &Config{
		ClientID:            "test",
		AllowedDomains:      []string{"example.com"},
		UserMapping:         UserMapping{Type: "email_prefix"},
		LogLevel:            "info",
		PollIntervalSeconds: 5,
		PollTimeoutSeconds:  -1,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative poll_timeout_seconds")
	}
	if !strings.Contains(err.Error(), "poll_timeout_seconds must be >= 1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientSecretPreserved(t *testing.T) {
	path := writeConfig(t, `
client_id: "test"
client_secret: "my-secret"
allowed_domains:
  - example.com
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret != "my-secret" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "my-secret")
	}
}

func TestFullConfig(t *testing.T) {
	path := writeConfig(t, `
client_id: "full-client"
client_secret: "full-secret"
scopes:
  - openid
  - email
  - profile
allowed_domains:
  - example.com
  - test.org
user_mapping:
  type: "static"
  mappings:
    alice@example.com: "alice"
    bob@test.org: "bob"
poll_interval_seconds: 3
poll_timeout_seconds: 120
log_level: "debug"
device_endpoint: "https://custom/device"
token_endpoint: "https://custom/token"
jwks_endpoint: "https://custom/jwks"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "full-client" {
		t.Errorf("ClientID mismatch")
	}
	if cfg.ClientSecret != "full-secret" {
		t.Errorf("ClientSecret mismatch")
	}
	if len(cfg.Scopes) != 3 {
		t.Errorf("Scopes count = %d, want 3", len(cfg.Scopes))
	}
	if len(cfg.AllowedDomains) != 2 {
		t.Errorf("AllowedDomains count = %d, want 2", len(cfg.AllowedDomains))
	}
	if cfg.UserMapping.Type != "static" {
		t.Errorf("UserMapping.Type = %q, want static", cfg.UserMapping.Type)
	}
	if len(cfg.UserMapping.Mappings) != 2 {
		t.Errorf("Mappings count = %d, want 2", len(cfg.UserMapping.Mappings))
	}
	if cfg.PollIntervalSeconds != 3 {
		t.Errorf("PollIntervalSeconds = %d, want 3", cfg.PollIntervalSeconds)
	}
	if cfg.PollTimeoutSeconds != 120 {
		t.Errorf("PollTimeoutSeconds = %d, want 120", cfg.PollTimeoutSeconds)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}
