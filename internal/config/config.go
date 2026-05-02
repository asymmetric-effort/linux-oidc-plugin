package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath   = "/etc/pam-oidc/config.yaml"
	DefaultPollInterval = 5
	DefaultPollTimeout  = 300
	DefaultLogLevel     = "info"
	EnvConfigPath       = "PAM_OIDC_CONFIG"
)

type UserMapping struct {
	Type     string            `yaml:"type"`
	Mappings map[string]string `yaml:"mappings,omitempty"`
}

type Config struct {
	ClientID            string      `yaml:"client_id"`
	ClientSecret        string      `yaml:"client_secret"`
	Scopes              []string    `yaml:"scopes"`
	AllowedDomains      []string    `yaml:"allowed_domains"`
	UserMapping         UserMapping `yaml:"user_mapping"`
	PollIntervalSeconds int         `yaml:"poll_interval_seconds"`
	PollTimeoutSeconds  int         `yaml:"poll_timeout_seconds"`
	LogLevel            string      `yaml:"log_level"`

	// Endpoints can be overridden for testing
	DeviceEndpoint string `yaml:"device_endpoint,omitempty"`
	TokenEndpoint  string `yaml:"token_endpoint,omitempty"`
	JWKSEndpoint   string `yaml:"jwks_endpoint,omitempty"`
}

func Load(path string) (*Config, error) {
	// Check env override
	if envPath := os.Getenv(EnvConfigPath); envPath != "" {
		path = envPath
	}
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "email"}
	}
	if c.PollIntervalSeconds == 0 {
		c.PollIntervalSeconds = DefaultPollInterval
	}
	if c.PollTimeoutSeconds == 0 {
		c.PollTimeoutSeconds = DefaultPollTimeout
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.UserMapping.Type == "" {
		c.UserMapping.Type = "email_prefix"
	}
	if c.DeviceEndpoint == "" {
		c.DeviceEndpoint = "https://oauth2.googleapis.com/device/code"
	}
	if c.TokenEndpoint == "" {
		c.TokenEndpoint = "https://oauth2.googleapis.com/token"
	}
	if c.JWKSEndpoint == "" {
		c.JWKSEndpoint = "https://www.googleapis.com/oauth2/v3/certs"
	}
}

func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("at least one allowed_domain is required")
	}
	if c.UserMapping.Type != "email_prefix" && c.UserMapping.Type != "static" {
		return fmt.Errorf("user_mapping.type must be 'email_prefix' or 'static', got %q", c.UserMapping.Type)
	}
	if c.UserMapping.Type == "static" && len(c.UserMapping.Mappings) == 0 {
		return fmt.Errorf("user_mapping.mappings is required when type is 'static'")
	}
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("log_level must be one of: debug, info, warn, error; got %q", c.LogLevel)
	}
	if c.PollIntervalSeconds < 1 {
		return fmt.Errorf("poll_interval_seconds must be >= 1")
	}
	if c.PollTimeoutSeconds < 1 {
		return fmt.Errorf("poll_timeout_seconds must be >= 1")
	}
	return nil
}
