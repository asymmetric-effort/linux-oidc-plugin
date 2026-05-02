package pam

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/config"
	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/oidc"
)

// --- Mock implementations ---

type mockDeviceFlowClient struct {
	deviceCodeResp *oidc.DeviceAuthResponse
	deviceCodeErr  error
	tokenResp      *oidc.TokenResponse
	tokenErr       error
}

func (m *mockDeviceFlowClient) RequestDeviceCode(_ context.Context, _, _ string, _ []string) (*oidc.DeviceAuthResponse, error) {
	return m.deviceCodeResp, m.deviceCodeErr
}

func (m *mockDeviceFlowClient) PollForToken(_ context.Context, _, _, _ string, _, _ int) (*oidc.TokenResponse, error) {
	return m.tokenResp, m.tokenErr
}

type mockTokenValidator struct {
	claims *oidc.Claims
	err    error
}

func (m *mockTokenValidator) ValidateIDToken(_ context.Context, _ string, _ string) (*oidc.Claims, error) {
	return m.claims, m.err
}

type mockUserMapper struct {
	username string
	err      error
}

func (m *mockUserMapper) MapEmailToUser(_ string) (string, error) {
	return m.username, m.err
}

// --- Test helpers ---

func testConfig() *config.Config {
	return &config.Config{
		ClientID:            "test-client-id",
		ClientSecret:        "test-secret",
		Scopes:              []string{"openid", "email"},
		AllowedDomains:      []string{"example.com"},
		PollIntervalSeconds: 5,
		PollTimeoutSeconds:  300,
		LogLevel:            "debug",
	}
}

func testDeviceResp() *oidc.DeviceAuthResponse {
	return &oidc.DeviceAuthResponse{
		DeviceCode:      "device-code-123",
		UserCode:        "ABCD-EFGH",
		VerificationURI: "https://example.com/device",
		ExpiresIn:       600,
		Interval:        5,
	}
}

func testTokenResp() *oidc.TokenResponse {
	return &oidc.TokenResponse{
		AccessToken: "access-token-123",
		IDToken:     "id-token-123",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
}

func testClaims() *oidc.Claims {
	return &oidc.Claims{
		Subject:       "subject-123",
		Email:         "testuser@example.com",
		EmailVerified: true,
		Issuer:        "https://accounts.google.com",
		Audience:      "test-client-id",
	}
}

func setupHandler(t *testing.T, stdin string, oidcClient DeviceFlowClient, validator TokenValidatorInterface, mapper UserMapperInterface) (*Handler, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("PAM_USER", "testuser")

	stdinBuf := bytes.NewBufferString(stdin)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	io := NewIOHandler(stdinBuf, stdout, stderr, "debug")
	cfg := testConfig()

	h := NewHandler(cfg, oidcClient, validator, mapper, io)
	return h, stdout, stderr
}

// --- Tests ---

func TestAuthenticate_Success(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{username: "testuser"}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitSuccess {
		t.Errorf("expected ExitSuccess (%d), got %d", ExitSuccess, exitCode)
	}
	if !strings.Contains(stdout.String(), "Authentication successful!") {
		t.Errorf("stdout should contain success message, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "authentication successful for user: testuser") {
		t.Errorf("stderr should contain success log, got: %s", stderr.String())
	}
}

func TestAuthenticate_ReadUsernameFails(t *testing.T) {
	t.Setenv("PAM_USER", "")

	client := &mockDeviceFlowClient{}
	validator := &mockTokenValidator{}
	mapper := &mockUserMapper{}

	stdinBuf := errReader{} // always returns error
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	io := NewIOHandler(stdinBuf, stdout, stderr, "debug")
	cfg := testConfig()
	h := NewHandler(cfg, client, validator, mapper, io)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitSysError {
		t.Errorf("expected ExitSysError (%d), got %d", ExitSysError, exitCode)
	}
	if !strings.Contains(stderr.String(), "failed to read username") {
		t.Errorf("stderr should contain username error, got: %s", stderr.String())
	}
}

func TestAuthenticate_DeviceCodeFails(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeErr: fmt.Errorf("device endpoint unavailable"),
	}
	validator := &mockTokenValidator{}
	mapper := &mockUserMapper{}

	h, _, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitSysError {
		t.Errorf("expected ExitSysError (%d), got %d", ExitSysError, exitCode)
	}
	if !strings.Contains(stderr.String(), "failed to request device code") {
		t.Errorf("stderr should contain device code error, got: %s", stderr.String())
	}
}

func TestAuthenticate_PollFails(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenErr:       fmt.Errorf("polling timed out"),
	}
	validator := &mockTokenValidator{}
	mapper := &mockUserMapper{}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitAuthError {
		t.Errorf("expected ExitAuthError (%d), got %d", ExitAuthError, exitCode)
	}
	if !strings.Contains(stderr.String(), "failed to obtain token") {
		t.Errorf("stderr should contain token error, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Authentication failed. Please try again.") {
		t.Errorf("stdout should contain failure message, got: %s", stdout.String())
	}
}

func TestAuthenticate_TokenValidationFails(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{err: fmt.Errorf("invalid signature")}
	mapper := &mockUserMapper{}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitAuthError {
		t.Errorf("expected ExitAuthError (%d), got %d", ExitAuthError, exitCode)
	}
	if !strings.Contains(stderr.String(), "token validation failed") {
		t.Errorf("stderr should contain validation error, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Authentication failed: invalid token.") {
		t.Errorf("stdout should contain invalid token message, got: %s", stdout.String())
	}
}

func TestAuthenticate_DomainNotAllowed(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{err: fmt.Errorf("domain %q is not in allowed domains", "evil.com")}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitAuthError {
		t.Errorf("expected ExitAuthError (%d), got %d", ExitAuthError, exitCode)
	}
	if !strings.Contains(stderr.String(), "user mapping failed") {
		t.Errorf("stderr should contain mapping error, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Authentication failed: user not authorized.") {
		t.Errorf("stdout should contain not authorized message, got: %s", stdout.String())
	}
}

func TestAuthenticate_UsernameMismatch(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{username: "differentuser"}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitAuthError {
		t.Errorf("expected ExitAuthError (%d), got %d", ExitAuthError, exitCode)
	}
	if !strings.Contains(stderr.String(), "username mismatch") {
		t.Errorf("stderr should contain mismatch error, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Authentication failed: username mismatch.") {
		t.Errorf("stdout should contain mismatch message, got: %s", stdout.String())
	}
}

func TestAuthenticate_UserMappingFails(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{err: fmt.Errorf("no mapping found for email")}

	h, stdout, stderr := setupHandler(t, "", client, validator, mapper)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitAuthError {
		t.Errorf("expected ExitAuthError (%d), got %d", ExitAuthError, exitCode)
	}
	if !strings.Contains(stderr.String(), "user mapping failed") {
		t.Errorf("stderr should contain mapping error, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Authentication failed: user not authorized.") {
		t.Errorf("stdout should contain not authorized message, got: %s", stdout.String())
	}
}

func TestAuthenticate_VerifiesOutputMessages(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{username: "testuser"}

	h, stdout, _ := setupHandler(t, "", client, validator, mapper)

	h.Authenticate(context.Background())

	output := stdout.String()
	if !strings.Contains(output, "https://example.com/device") {
		t.Errorf("stdout should contain verification URI, got: %s", output)
	}
	if !strings.Contains(output, "ABCD-EFGH") {
		t.Errorf("stdout should contain user code, got: %s", output)
	}
	if !strings.Contains(output, "To sign in") {
		t.Errorf("stdout should contain sign-in instructions, got: %s", output)
	}
}

func TestAuthenticate_VerifiesLogMessages(t *testing.T) {
	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{username: "testuser"}

	h, _, stderr := setupHandler(t, "", client, validator, mapper)

	h.Authenticate(context.Background())

	logs := stderr.String()
	expectedLogs := []string{
		"[INFO] starting OIDC authentication",
		"[INFO] authenticating user: testuser",
		"[DEBUG] device code issued, expires in 600 seconds",
		"[INFO] token received, validating...",
		"[INFO] token validated for email: testuser@example.com",
		"[INFO] authentication successful for user: testuser",
	}
	for _, expected := range expectedLogs {
		if !strings.Contains(logs, expected) {
			t.Errorf("stderr should contain %q, got: %s", expected, logs)
		}
	}
}

func TestNewHandler(t *testing.T) {
	cfg := testConfig()
	client := &mockDeviceFlowClient{}
	validator := &mockTokenValidator{}
	mapper := &mockUserMapper{}
	io := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	h := NewHandler(cfg, client, validator, mapper, io)

	if h.Config != cfg {
		t.Error("Config not set correctly")
	}
	if h.OIDCClient != client {
		t.Error("OIDCClient not set correctly")
	}
	if h.TokenValidator != validator {
		t.Error("TokenValidator not set correctly")
	}
	if h.UserMapper != mapper {
		t.Error("UserMapper not set correctly")
	}
	if h.IO != io {
		t.Error("IO not set correctly")
	}
}

func TestAuthenticate_ReadUsernameNoEnvNoStdin(t *testing.T) {
	t.Setenv("PAM_USER", "")

	client := &mockDeviceFlowClient{}
	validator := &mockTokenValidator{}
	mapper := &mockUserMapper{}

	stdinBuf := bytes.NewBufferString("")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	io := NewIOHandler(stdinBuf, stdout, stderr, "debug")
	cfg := testConfig()
	h := NewHandler(cfg, client, validator, mapper, io)

	exitCode := h.Authenticate(context.Background())
	if exitCode != ExitSysError {
		t.Errorf("expected ExitSysError (%d), got %d", ExitSysError, exitCode)
	}
	if !strings.Contains(stderr.String(), "failed to read username") {
		t.Errorf("stderr should contain username error, got: %s", stderr.String())
	}
}

// errWriter is an io.Writer that always returns an error.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write error") }

func TestAuthenticate_DisplayMessageError(t *testing.T) {
	// When stdout fails to write, the handler should still succeed (display
	// errors are best-effort) and log a warning about the display failure.
	t.Setenv("PAM_USER", "testuser")

	client := &mockDeviceFlowClient{
		deviceCodeResp: testDeviceResp(),
		tokenResp:      testTokenResp(),
	}
	validator := &mockTokenValidator{claims: testClaims()}
	mapper := &mockUserMapper{username: "testuser"}

	stderrBuf := &bytes.Buffer{}
	failWriter := errWriter{}
	io := NewIOHandler(bytes.NewBufferString(""), failWriter, stderrBuf, "debug")
	cfg := testConfig()

	h := NewHandler(cfg, client, validator, mapper, io)
	exitCode := h.Authenticate(context.Background())

	if exitCode != ExitSuccess {
		t.Errorf("expected ExitSuccess (%d), got %d", ExitSuccess, exitCode)
	}
	if !strings.Contains(stderrBuf.String(), "failed to display verification info") {
		t.Errorf("stderr should contain display failure warning, got: %s", stderrBuf.String())
	}
}

func TestExitCodeConstants(t *testing.T) {
	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess should be 0, got %d", ExitSuccess)
	}
	if ExitAuthError != 1 {
		t.Errorf("ExitAuthError should be 1, got %d", ExitAuthError)
	}
	if ExitSysError != 2 {
		t.Errorf("ExitSysError should be 2, got %d", ExitSysError)
	}
}
