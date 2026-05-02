package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

type Client struct {
	HTTPClient     *http.Client
	DeviceEndpoint string
	TokenEndpoint  string
}

func NewClient(httpClient *http.Client, deviceEndpoint, tokenEndpoint string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		HTTPClient:     httpClient,
		DeviceEndpoint: deviceEndpoint,
		TokenEndpoint:  tokenEndpoint,
	}
}

func (c *Client) RequestDeviceCode(ctx context.Context, clientID, clientSecret string, scopes []string) (*DeviceAuthResponse, error) {
	data := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.DeviceEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("device code request failed: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("device code request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp DeviceAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}

	return &authResp, nil
}

func (c *Client) PollForToken(ctx context.Context, clientID, clientSecret, deviceCode string, interval, timeout int) (*TokenResponse, error) {
	if interval < 1 {
		interval = 5
	}

	deadline := time.After(time.Duration(timeout) * time.Second)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("polling timed out after %d seconds", timeout)
		case <-ticker.C:
			tokenResp, err := c.requestToken(ctx, clientID, clientSecret, deviceCode)
			if err != nil {
				// Check if it's a polling error we should retry
				if pollErr, ok := err.(*PollError); ok {
					switch pollErr.ErrorCode {
					case "authorization_pending":
						continue
					case "slow_down":
						ticker.Stop()
						interval += 5
						ticker = time.NewTicker(time.Duration(interval) * time.Second)
						continue
					case "access_denied":
						return nil, fmt.Errorf("access denied by user")
					case "expired_token":
						return nil, fmt.Errorf("device code expired")
					}
				}
				return nil, err
			}
			return tokenResp, nil
		}
	}
}

type PollError struct {
	ErrorCode        string
	ErrorDescription string
}

func (e *PollError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
}

func (c *Client) requestToken(ctx context.Context, clientID, clientSecret, deviceCode string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":   {clientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, &PollError{
				ErrorCode:        errResp.Error,
				ErrorDescription: errResp.ErrorDescription,
			}
		}
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	return &tokenResp, nil
}
