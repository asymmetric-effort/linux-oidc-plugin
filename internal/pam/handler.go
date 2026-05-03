package pam

import (
	"context"
	"fmt"

	"github.com/asymmetric-effort/linux-oidc-plugin/internal/config"
	"github.com/asymmetric-effort/linux-oidc-plugin/internal/oidc"
)

const (
	ExitSuccess   = 0
	ExitAuthError = 1
	ExitSysError  = 2
)

// DeviceFlowClient abstracts the OIDC device flow operations
type DeviceFlowClient interface {
	RequestDeviceCode(ctx context.Context, clientID, clientSecret string, scopes []string) (*oidc.DeviceAuthResponse, error)
	PollForToken(ctx context.Context, clientID, clientSecret, deviceCode string, interval, timeout int) (*oidc.TokenResponse, error)
}

// TokenValidatorInterface abstracts token validation
type TokenValidatorInterface interface {
	ValidateIDToken(ctx context.Context, rawToken string, expectedAudience string) (*oidc.Claims, error)
}

// UserMapperInterface abstracts user mapping
type UserMapperInterface interface {
	MapEmailToUser(email string) (string, error)
}

type Handler struct {
	Config         *config.Config
	OIDCClient     DeviceFlowClient
	TokenValidator TokenValidatorInterface
	UserMapper     UserMapperInterface
	IO             *IOHandler
}

func NewHandler(cfg *config.Config, oidcClient DeviceFlowClient, tokenValidator TokenValidatorInterface, userMapper UserMapperInterface, ioHandler *IOHandler) *Handler {
	return &Handler{
		Config:         cfg,
		OIDCClient:     oidcClient,
		TokenValidator: tokenValidator,
		UserMapper:     userMapper,
		IO:             ioHandler,
	}
}

func (h *Handler) Authenticate(ctx context.Context) int {
	h.IO.LogInfo("starting OIDC authentication")

	// Step 1: Read username
	username, err := h.IO.ReadUsername()
	if err != nil {
		h.IO.LogError(fmt.Sprintf("failed to read username: %v", err))
		return ExitSysError
	}
	h.IO.LogInfo(fmt.Sprintf("authenticating user: %s", username))

	// Step 2: Request device code
	deviceResp, err := h.OIDCClient.RequestDeviceCode(ctx, h.Config.ClientID, h.Config.ClientSecret, h.Config.Scopes)
	if err != nil {
		h.IO.LogError(fmt.Sprintf("failed to request device code: %v", err))
		return ExitSysError
	}

	// Step 3: Display verification info to user
	if err := h.IO.DisplayMessage(fmt.Sprintf("\nTo sign in, open your browser and visit:\n  %s\n\nEnter the code: %s\n", deviceResp.VerificationURI, deviceResp.UserCode)); err != nil {
		h.IO.LogWarn(fmt.Sprintf("failed to display verification info: %v", err))
	}
	h.IO.LogDebug(fmt.Sprintf("device code issued, expires in %d seconds", deviceResp.ExpiresIn))

	// Step 4: Poll for token
	tokenResp, err := h.OIDCClient.PollForToken(ctx, h.Config.ClientID, h.Config.ClientSecret, deviceResp.DeviceCode, h.Config.PollIntervalSeconds, h.Config.PollTimeoutSeconds)
	if err != nil {
		h.IO.LogError(fmt.Sprintf("failed to obtain token: %v", err))
		_ = h.IO.DisplayMessage("Authentication failed. Please try again.") // best-effort user message
		return ExitAuthError
	}
	h.IO.LogInfo("token received, validating...")

	// Step 5: Validate ID token
	claims, err := h.TokenValidator.ValidateIDToken(ctx, tokenResp.IDToken, h.Config.ClientID)
	if err != nil {
		h.IO.LogError(fmt.Sprintf("token validation failed: %v", err))
		_ = h.IO.DisplayMessage("Authentication failed: invalid token.") // best-effort user message
		return ExitAuthError
	}
	h.IO.LogInfo(fmt.Sprintf("token validated for email: %s", claims.Email))

	// Step 6: Map email to username
	mappedUser, err := h.UserMapper.MapEmailToUser(claims.Email)
	if err != nil {
		h.IO.LogError(fmt.Sprintf("user mapping failed: %v", err))
		_ = h.IO.DisplayMessage("Authentication failed: user not authorized.") // best-effort user message
		return ExitAuthError
	}

	// Step 7: Compare mapped username to PAM username
	if mappedUser != username {
		h.IO.LogError(fmt.Sprintf("username mismatch: PAM user %q != mapped user %q", username, mappedUser))
		_ = h.IO.DisplayMessage("Authentication failed: username mismatch.") // best-effort user message
		return ExitAuthError
	}

	h.IO.LogInfo(fmt.Sprintf("authentication successful for user: %s", username))
	_ = h.IO.DisplayMessage("Authentication successful!") // best-effort user message
	return ExitSuccess
}
