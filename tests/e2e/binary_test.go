package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Local types mirroring internal/ types (cannot import internal/ from e2e tests)

type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
}

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary once for all tests
	tmpDir, err := os.MkdirTemp("", "pam-oidc-e2e-*")
	if err != nil {
		panic("creating temp dir: " + err.Error())
	}
	binaryPath = filepath.Join(tmpDir, "pam-oidc")

	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/pam-oidc")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Stderr.WriteString("FATAL: could not build binary for e2e tests: " + err.Error() + "\n")
		os.RemoveAll(tmpDir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

// mockServer is a mock OIDC server for e2e tests.
type mockServer struct {
	key            *rsa.PrivateKey
	kid            string
	server         *httptest.Server
	tokenCallCount atomic.Int32
	tokenBehavior  string // "success", "pending_then_success", "access_denied", "always_pending"
	emailInToken   string
}

func newMockServer(t *testing.T, behavior, email string) *mockServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	m := &mockServer{
		key:           key,
		kid:           "e2e-test-key",
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

func (m *mockServer) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	resp := DeviceAuthResponse{
		DeviceCode:              "e2e-device-code",
		UserCode:                "E2E-CODE",
		VerificationURI:         "https://example.com/device",
		VerificationURIComplete: "https://example.com/device?code=E2E-CODE",
		ExpiresIn:               300,
		Interval:                1,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockServer) handleToken(w http.ResponseWriter, r *http.Request) {
	callNum := m.tokenCallCount.Add(1)

	switch m.tokenBehavior {
	case "success":
		m.writeTokenSuccess(w)
	case "pending_then_success":
		if callNum <= 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:            "authorization_pending",
				ErrorDescription: "waiting for user",
			})
		} else {
			m.writeTokenSuccess(w)
		}
	case "access_denied":
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "user denied access",
		})
	case "always_pending":
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "authorization_pending",
			ErrorDescription: "waiting for user",
		})
	}
}

func (m *mockServer) writeTokenSuccess(w http.ResponseWriter) {
	idToken := m.createSignedJWT()
	resp := TokenResponse{
		AccessToken: "mock-access-token",
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockServer) createSignedJWT() string {
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

	signed, err := token.SignedString(m.key)
	if err != nil {
		panic("signing JWT: " + err.Error())
	}
	return signed
}

func (m *mockServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pubKey := &m.key.PublicKey
	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()

	jwks := JWKSResponse{
		Keys: []JWK{
			{
				Kid: m.kid,
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// writeConfigFile writes a YAML config file for the binary and returns its path.
func writeConfigFile(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `client_id: test-client-id
scopes:
  - openid
  - email
allowed_domains:
  - example.com
user_mapping:
  type: email_prefix
poll_interval_seconds: 1
poll_timeout_seconds: 10
log_level: debug
device_endpoint: ` + serverURL + `/device/code
token_endpoint: ` + serverURL + `/token
jwks_endpoint: ` + serverURL + `/jwks
`

	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	return cfgPath
}

// runBinary runs the pam-oidc binary with the given env vars and returns exit code, stdout, stderr.
func runBinary(t *testing.T, env map[string]string, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Start with a clean env, carrying over PATH and HOME
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("running binary: %v", err)
		}
	}

	return exitCode, stdoutBuf.String(), stderrBuf.String()
}

func TestE2E_Version(t *testing.T) {
	exitCode, stdout, _ := runBinary(t, nil, "--version")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(strings.ToLower(stdout), "pam-oidc") {
		t.Errorf("expected stdout to contain 'pam-oidc', got: %s", stdout)
	}
}

func TestE2E_SuccessfulAuth(t *testing.T) {
	mock := newMockServer(t, "pending_then_success", "testuser@example.com")
	cfgPath := writeConfigFile(t, mock.server.URL)

	exitCode, stdout, stderr := runBinary(t, map[string]string{
		"PAM_OIDC_CONFIG": cfgPath,
		"PAM_USER":        "testuser",
	})

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "https://example.com/device") {
		t.Errorf("stdout should contain verification URL, got: %s", stdout)
	}
	if !strings.Contains(stdout, "E2E-CODE") {
		t.Errorf("stdout should contain user code, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Authentication successful") {
		t.Errorf("stdout should contain success message, got: %s", stdout)
	}
}

func TestE2E_AuthDenied(t *testing.T) {
	mock := newMockServer(t, "access_denied", "testuser@example.com")
	cfgPath := writeConfigFile(t, mock.server.URL)

	exitCode, stdout, stderr := runBinary(t, map[string]string{
		"PAM_OIDC_CONFIG": cfgPath,
		"PAM_USER":        "testuser",
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "Authentication failed") {
		t.Errorf("stdout should contain failure message, got: %s", stdout)
	}
}

func TestE2E_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("{{{{not valid yaml!!!!"), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	exitCode, _, _ := runBinary(t, map[string]string{
		"PAM_OIDC_CONFIG": cfgPath,
		"PAM_USER":        "testuser",
	})

	if exitCode != 2 {
		t.Errorf("expected exit code 2, got %d", exitCode)
	}
}

func TestE2E_MissingConfig(t *testing.T) {
	exitCode, _, _ := runBinary(t, map[string]string{
		"PAM_OIDC_CONFIG": "/nonexistent/path/config.yaml",
		"PAM_USER":        "testuser",
	})

	if exitCode != 2 {
		t.Errorf("expected exit code 2, got %d", exitCode)
	}
}

func TestE2E_UsernameMismatch(t *testing.T) {
	mock := newMockServer(t, "success", "alice@example.com")
	cfgPath := writeConfigFile(t, mock.server.URL)

	exitCode, stdout, stderr := runBinary(t, map[string]string{
		"PAM_OIDC_CONFIG": cfgPath,
		"PAM_USER":        "bob",
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "username mismatch") {
		t.Errorf("stdout should contain username mismatch, got: %s", stdout)
	}
}
