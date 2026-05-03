package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/asymmetric-effort/linux-oidc-plugin/internal/config"
	"github.com/asymmetric-effort/linux-oidc-plugin/internal/oidc"
	"github.com/asymmetric-effort/linux-oidc-plugin/internal/pam"
	"github.com/asymmetric-effort/linux-oidc-plugin/internal/user"
)

type mockOIDCServer struct {
	key              *rsa.PrivateKey
	kid              string
	server           *httptest.Server
	tokenCallCount   atomic.Int32
	tokenBehavior    string // "success", "pending_then_success", "access_denied", "always_pending"
	emailInToken     string
	wrongKeyForToken bool // sign with a different key
}

func newMockOIDCServer(t *testing.T, behavior, email string) *mockOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	m := &mockOIDCServer{
		key:           key,
		kid:           "test-key-1",
		tokenBehavior: behavior,
		emailInToken:  email,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", m.handleDeviceCode)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/jwks", m.handleJWKS)

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)

	return m
}

func (m *mockOIDCServer) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]interface{}{
		"device_code":              "test-device-code",
		"user_code":                "ABCD-1234",
		"verification_uri":         "https://example.com/device",
		"verification_uri_complete": "https://example.com/device?code=ABCD-1234",
		"expires_in":               300,
		"interval":                 1,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	callNum := m.tokenCallCount.Add(1)

	switch m.tokenBehavior {
	case "success":
		m.writeTokenSuccess(w)
	case "pending_then_success":
		if callNum <= 1 {
			m.writeError(w, "authorization_pending", "waiting for user")
		} else {
			m.writeTokenSuccess(w)
		}
	case "access_denied":
		m.writeError(w, "access_denied", "user denied access")
	case "always_pending":
		m.writeError(w, "authorization_pending", "waiting for user")
	default:
		m.writeTokenSuccess(w)
	}
}

func (m *mockOIDCServer) writeTokenSuccess(w http.ResponseWriter) {
	idToken := m.createSignedJWT()
	resp := map[string]interface{}{
		"access_token": "mock-access-token",
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCServer) writeError(w http.ResponseWriter, code, description string) {
	w.WriteHeader(http.StatusBadRequest)
	resp := map[string]string{
		"error":             code,
		"error_description": description,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCServer) createSignedJWT() string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"sub":            "1234567890",
		"aud":            "test-client-id",
		"email":          m.emailInToken,
		"email_verified": true,
		"exp":            now.Add(1 * time.Hour).Unix(),
		"iat":            now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid

	signingKey := m.key
	if m.wrongKeyForToken {
		// Generate a different key to sign with
		wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		signingKey = wrongKey
	}

	signed, err := token.SignedString(signingKey)
	if err != nil {
		panic("signing JWT: " + err.Error())
	}
	return signed
}

func (m *mockOIDCServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pubKey := &m.key.PublicKey
	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()

	jwks := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kid": m.kid,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func makeConfig(server *httptest.Server) *config.Config {
	return &config.Config{
		ClientID:            "test-client-id",
		Scopes:              []string{"openid", "email"},
		AllowedDomains:      []string{"example.com"},
		UserMapping:         config.UserMapping{Type: "email_prefix"},
		PollIntervalSeconds: 1,
		PollTimeoutSeconds:  10,
		LogLevel:            "debug",
		DeviceEndpoint:      server.URL + "/device/code",
		TokenEndpoint:       server.URL + "/token",
		JWKSEndpoint:        server.URL + "/jwks",
	}
}

func runAuth(t *testing.T, cfg *config.Config) (exitCode int, stdout, stderr string) {
	t.Helper()
	var stdoutBuf, stderrBuf bytes.Buffer

	oidcClient := oidc.NewClient(nil, cfg.DeviceEndpoint, cfg.TokenEndpoint)
	tokenValidator := oidc.NewTokenValidator(cfg.JWKSEndpoint, nil)
	mapper := user.NewMapper(cfg.UserMapping.Type, cfg.UserMapping.Mappings, cfg.AllowedDomains)
	ioHandler := pam.NewIOHandler(nil, &stdoutBuf, &stderrBuf, cfg.LogLevel)

	handler := pam.NewHandler(cfg, oidcClient, tokenValidator, mapper, ioHandler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exitCode = handler.Authenticate(ctx)
	return exitCode, stdoutBuf.String(), stderrBuf.String()
}

func TestIntegration_SuccessfulAuth(t *testing.T) {
	mock := newMockOIDCServer(t, "pending_then_success", "testuser@example.com")
	cfg := makeConfig(mock.server)

	t.Setenv("PAM_USER", "testuser")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "https://example.com/device") {
		t.Errorf("stdout should contain verification URL, got: %s", stdout)
	}
	if !strings.Contains(stdout, "ABCD-1234") {
		t.Errorf("stdout should contain user code, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Authentication successful") {
		t.Errorf("stdout should contain success message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "starting OIDC authentication") {
		t.Errorf("stderr should contain log line about starting auth, got: %s", stderr)
	}
	if !strings.Contains(stderr, "token validated") {
		t.Errorf("stderr should contain log line about token validation, got: %s", stderr)
	}
	if !strings.Contains(stderr, "authentication successful") {
		t.Errorf("stderr should contain log line about successful auth, got: %s", stderr)
	}
}

func TestIntegration_AccessDenied(t *testing.T) {
	mock := newMockOIDCServer(t, "access_denied", "testuser@example.com")
	cfg := makeConfig(mock.server)

	t.Setenv("PAM_USER", "testuser")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "Authentication failed") {
		t.Errorf("stdout should contain failure message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "failed to obtain token") {
		t.Errorf("stderr should contain token failure log, got: %s", stderr)
	}
}

func TestIntegration_WrongUser(t *testing.T) {
	mock := newMockOIDCServer(t, "success", "other@example.com")
	cfg := makeConfig(mock.server)

	t.Setenv("PAM_USER", "testuser")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "username mismatch") {
		t.Errorf("stdout should contain username mismatch message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "username mismatch") {
		t.Errorf("stderr should contain username mismatch log, got: %s", stderr)
	}
}

func TestIntegration_DomainNotAllowed(t *testing.T) {
	mock := newMockOIDCServer(t, "success", "user@evil.com")
	cfg := makeConfig(mock.server)

	t.Setenv("PAM_USER", "user")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "not authorized") {
		t.Errorf("stdout should contain not authorized message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "user mapping failed") {
		t.Errorf("stderr should contain user mapping failure log, got: %s", stderr)
	}
}

func TestIntegration_InvalidToken(t *testing.T) {
	mock := newMockOIDCServer(t, "success", "testuser@example.com")
	mock.wrongKeyForToken = true
	cfg := makeConfig(mock.server)

	t.Setenv("PAM_USER", "testuser")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "invalid token") {
		t.Errorf("stdout should contain invalid token message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "token validation failed") {
		t.Errorf("stderr should contain token validation failure log, got: %s", stderr)
	}
}

func TestIntegration_Timeout(t *testing.T) {
	mock := newMockOIDCServer(t, "always_pending", "testuser@example.com")
	cfg := makeConfig(mock.server)
	cfg.PollTimeoutSeconds = 2
	cfg.PollIntervalSeconds = 1

	t.Setenv("PAM_USER", "testuser")

	exitCode, stdout, stderr := runAuth(t, cfg)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "Authentication failed") {
		t.Errorf("stdout should contain failure message, got: %s", stdout)
	}
	if !strings.Contains(stderr, "failed to obtain token") {
		t.Errorf("stderr should contain token failure log, got: %s", stderr)
	}
}
