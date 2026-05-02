package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRun_Version(t *testing.T) {
	code := run([]string{"pam-oidc", "--version"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --version, got %d", code)
	}
}

func TestRun_NoArgs(t *testing.T) {
	// With no --version and default config path, should fail to load config
	t.Setenv("PAM_OIDC_CONFIG", "")
	code := run([]string{"pam-oidc"})
	if code != 2 {
		t.Errorf("expected exit code 2 for default missing config, got %d", code)
	}
}

func TestRun_MissingConfig(t *testing.T) {
	t.Setenv("PAM_OIDC_CONFIG", "/nonexistent/path/config.yaml")
	code := run([]string{"pam-oidc"})
	if code != 2 {
		t.Errorf("expected exit code 2 for missing config, got %d", code)
	}
}

func TestRun_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("{{{{not valid yaml"), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("PAM_OIDC_CONFIG", cfgPath)
	code := run([]string{"pam-oidc"})
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid config, got %d", code)
	}
}

func TestRun_ValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("allowed_domains:\n  - example.com\n"), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("PAM_OIDC_CONFIG", cfgPath)
	code := run([]string{"pam-oidc"})
	if code != 2 {
		t.Errorf("expected exit code 2 for validation error, got %d", code)
	}
}

func TestVersion_Variable(t *testing.T) {
	if version == "" {
		t.Error("version should not be empty")
	}
}

// TestRun_ValidConfigNoUsername exercises the full setup path (config load,
// dependency creation, handler creation) with a valid config. The handler
// fails at username read since no PAM_USER or stdin is available, returning
// ExitSysError (2). This covers lines 36-53 of main.go.
func TestRun_ValidConfigNoUsername(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := `client_id: test-client
allowed_domains:
  - example.com
device_endpoint: ` + srv.URL + `/device
token_endpoint: ` + srv.URL + `/token
jwks_endpoint: ` + srv.URL + `/jwks
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	t.Setenv("PAM_OIDC_CONFIG", cfgPath)
	t.Setenv("PAM_USER", "")

	// Redirect stdin to empty so ReadUsername fails
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	code := run([]string{"pam-oidc"})
	// Should get ExitSysError (2) because no username is available
	if code != 2 {
		t.Errorf("expected exit code 2 (no username), got %d", code)
	}
}

// TestRun_FullSuccessPath exercises the entire run() function including
// successful authentication through a mock OIDC server.
func TestRun_FullSuccessPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	kid := "test-key-run"

	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dc-123",
			"user_code":        "RUN-TEST",
			"verification_uri": "https://example.com/device",
			"expires_in":       300,
			"interval":         1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := tokenCalls.Add(1)
		if n <= 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "waiting",
			})
			return
		}
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":            "https://accounts.google.com",
			"sub":            "user-abc",
			"aud":            "test-client",
			"email":          "runuser@example.com",
			"email_verified": true,
			"exp":            float64(now.Add(1 * time.Hour).Unix()),
			"iat":            float64(now.Unix()),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-123",
			"id_token":     signed,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &key.PublicKey
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{
					"kid": kid,
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := strings.Join([]string{
		"client_id: test-client",
		"allowed_domains:",
		"  - example.com",
		"poll_interval_seconds: 1",
		"poll_timeout_seconds: 10",
		"log_level: debug",
		"device_endpoint: " + srv.URL + "/device/code",
		"token_endpoint: " + srv.URL + "/token",
		"jwks_endpoint: " + srv.URL + "/jwks",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	t.Setenv("PAM_OIDC_CONFIG", cfgPath)
	t.Setenv("PAM_USER", "runuser")

	code := run([]string{"pam-oidc"})
	if code != 0 {
		t.Errorf("expected exit code 0 for successful auth, got %d", code)
	}
}
