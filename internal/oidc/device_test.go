package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClient_NilHTTPClient(t *testing.T) {
	c := NewClient(nil, "http://device", "http://token")
	if c.HTTPClient == nil {
		t.Fatal("expected non-nil HTTPClient when nil was passed")
	}
	if c.DeviceEndpoint != "http://device" {
		t.Fatalf("expected DeviceEndpoint to be %q, got %q", "http://device", c.DeviceEndpoint)
	}
	if c.TokenEndpoint != "http://token" {
		t.Fatalf("expected TokenEndpoint to be %q, got %q", "http://token", c.TokenEndpoint)
	}
}

func TestRequestDeviceCode_Success(t *testing.T) {
	expected := DeviceAuthResponse{
		DeviceCode:              "dev-code-123",
		UserCode:                "USER-1234",
		VerificationURI:         "https://example.com/activate",
		VerificationURIComplete: "https://example.com/activate?user_code=USER-1234",
		ExpiresIn:               1800,
		Interval:                5,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("client_id") != "my-client" {
			t.Errorf("expected client_id=my-client, got %s", r.FormValue("client_id"))
		}
		if r.FormValue("scope") != "openid email" {
			t.Errorf("expected scope=openid email, got %s", r.FormValue("scope"))
		}
		// client_secret should not be present
		if r.FormValue("client_secret") != "" {
			t.Errorf("expected no client_secret, got %s", r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "")
	resp, err := c.RequestDeviceCode(context.Background(), "my-client", "", []string{"openid", "email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DeviceCode != expected.DeviceCode {
		t.Errorf("expected DeviceCode=%q, got %q", expected.DeviceCode, resp.DeviceCode)
	}
	if resp.UserCode != expected.UserCode {
		t.Errorf("expected UserCode=%q, got %q", expected.UserCode, resp.UserCode)
	}
	if resp.VerificationURI != expected.VerificationURI {
		t.Errorf("expected VerificationURI=%q, got %q", expected.VerificationURI, resp.VerificationURI)
	}
	if resp.VerificationURIComplete != expected.VerificationURIComplete {
		t.Errorf("expected VerificationURIComplete=%q, got %q", expected.VerificationURIComplete, resp.VerificationURIComplete)
	}
	if resp.ExpiresIn != expected.ExpiresIn {
		t.Errorf("expected ExpiresIn=%d, got %d", expected.ExpiresIn, resp.ExpiresIn)
	}
	if resp.Interval != expected.Interval {
		t.Errorf("expected Interval=%d, got %d", expected.Interval, resp.Interval)
	}
}

func TestRequestDeviceCode_WithClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("client_secret") != "my-secret" {
			t.Errorf("expected client_secret=my-secret, got %q", r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceAuthResponse{
			DeviceCode: "code",
			UserCode:   "USER",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "")
	resp, err := c.RequestDeviceCode(context.Background(), "my-client", "my-secret", []string{"openid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DeviceCode != "code" {
		t.Errorf("expected DeviceCode=code, got %q", resp.DeviceCode)
	}
}

func TestRequestDeviceCode_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "")
	_, err := c.RequestDeviceCode(context.Background(), "my-client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected error to contain 'status 500', got %q", err.Error())
	}
}

func TestRequestDeviceCode_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "client not found",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "")
	_, err := c.RequestDeviceCode(context.Background(), "bad-client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("expected error to contain 'invalid_client', got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "client not found") {
		t.Errorf("expected error to contain 'client not found', got %q", err.Error())
	}
}

func TestRequestDeviceCode_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "")
	_, err := c.RequestDeviceCode(context.Background(), "my-client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing device code response") {
		t.Errorf("expected error about parsing, got %q", err.Error())
	}
}

func TestRequestDeviceCode_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := NewClient(srv.Client(), srv.URL, "")
	_, err := c.RequestDeviceCode(ctx, "my-client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "requesting device code") {
		t.Errorf("expected error about requesting device code, got %q", err.Error())
	}
}

func TestPollForToken_ImmediateSuccess(t *testing.T) {
	expected := TokenResponse{
		AccessToken: "access-tok",
		IDToken:     "id-tok",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("device_code") != "dev-code" {
			t.Errorf("unexpected device_code: %s", r.FormValue("device_code"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	resp, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != expected.AccessToken {
		t.Errorf("expected AccessToken=%q, got %q", expected.AccessToken, resp.AccessToken)
	}
	if resp.IDToken != expected.IDToken {
		t.Errorf("expected IDToken=%q, got %q", expected.IDToken, resp.IDToken)
	}
}

func TestPollForToken_PendingThenSuccess(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:            "authorization_pending",
				ErrorDescription: "user has not yet authorized",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "access-tok",
			IDToken:     "id-tok",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	resp, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "access-tok" {
		t.Errorf("expected AccessToken=access-tok, got %q", resp.AccessToken)
	}
	finalCount := callCount.Load()
	if finalCount < 3 {
		t.Errorf("expected at least 3 calls, got %d", finalCount)
	}
}

func TestPollForToken_SlowDown(t *testing.T) {
	var callCount atomic.Int32
	var callTimes []time.Time

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callTimes = append(callTimes, time.Now())
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error:            "slow_down",
				ErrorDescription: "please slow down",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "access-tok",
			IDToken:     "id-tok",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	start := time.Now()
	resp, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "access-tok" {
		t.Errorf("expected AccessToken=access-tok, got %q", resp.AccessToken)
	}
	// After slow_down, interval should increase by 5 (1+5=6 seconds).
	// The second call should be at least 5 seconds after the first.
	elapsed := time.Since(start)
	if elapsed < 5*time.Second {
		t.Errorf("expected at least 5s delay after slow_down, elapsed: %v", elapsed)
	}
}

func TestPollForToken_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "user denied access",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 5)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected 'access denied' error, got %q", err.Error())
	}
}

func TestPollForToken_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "expired_token",
			ErrorDescription: "the device code has expired",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 5)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "device code expired") {
		t.Errorf("expected 'device code expired' error, got %q", err.Error())
	}
}

func TestPollForToken_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "authorization_pending",
			ErrorDescription: "still waiting",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 2)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got %q", err.Error())
	}
}

func TestPollForToken_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "authorization_pending",
			ErrorDescription: "still waiting",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(ctx, "my-client", "", "dev-code", 1, 30)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should get context deadline exceeded or context canceled
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got %q", err.Error())
	}
}

func TestPollForToken_DefaultInterval(t *testing.T) {
	// When interval < 1, it should default to 5. We verify by checking that
	// the poll takes at least 5 seconds for the first tick.
	// To keep the test fast, we use context cancellation.
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "tok",
			IDToken:     "id",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c := NewClient(srv.Client(), "", srv.URL)
	// interval=0, so it defaults to 5. With a 3s context timeout, it should
	// timeout before the first tick fires (ticker at 5s).
	_, err := c.PollForToken(ctx, "my-client", "", "dev-code", 0, 30)
	if err == nil {
		t.Fatal("expected error due to context timeout before 5s tick")
	}
	// Should not have made any calls since the ticker hasn't fired in 3s
	if callCount.Load() != 0 {
		t.Errorf("expected 0 calls (default 5s interval > 3s timeout), got %d", callCount.Load())
	}
}

func TestPollForToken_NonPollError(t *testing.T) {
	// Server returns a non-JSON error (status 500 with plain text)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server broke"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 5)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token request failed with status 500") {
		t.Errorf("expected status 500 error, got %q", err.Error())
	}
}

func TestPollForToken_WithClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("client_secret") != "secret123" {
			t.Errorf("expected client_secret=secret123, got %q", r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "tok",
			IDToken:     "id",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	resp, err := c.PollForToken(context.Background(), "my-client", "secret123", "dev-code", 1, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("expected AccessToken=tok, got %q", resp.AccessToken)
	}
}

func TestPollForToken_InvalidTokenJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad json"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	_, err := c.PollForToken(context.Background(), "my-client", "", "dev-code", 1, 5)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing token response") {
		t.Errorf("expected parsing error, got %q", err.Error())
	}
}

func TestPollError_Error(t *testing.T) {
	pe := &PollError{
		ErrorCode:        "authorization_pending",
		ErrorDescription: "waiting for user",
	}
	expected := "authorization_pending: waiting for user"
	if pe.Error() != expected {
		t.Errorf("expected %q, got %q", expected, pe.Error())
	}
}

// errReadCloser is an io.ReadCloser whose Read always fails. This is used to
// test the io.ReadAll error path inside RequestDeviceCode and requestToken.
// In production, this path triggers when the HTTP response body is truncated
// or the connection drops mid-read -- an edge case that is difficult to
// reproduce with httptest but is reachable in real network conditions.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read body error") }
func (errReadCloser) Close() error              { return nil }

// roundTripFunc adapts a function to http.RoundTripper for injecting custom responses.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRequestDeviceCode_ReadBodyError(t *testing.T) {
	// Inject an HTTP response with a body that always fails on Read.
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errReadCloser{},
			Header:     make(http.Header),
		}, nil
	})
	c := NewClient(&http.Client{Transport: transport}, "http://device", "")
	_, err := c.RequestDeviceCode(context.Background(), "client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error for body read failure")
	}
	if !strings.Contains(err.Error(), "reading device code response") {
		t.Errorf("expected 'reading device code response' error, got %q", err.Error())
	}
}

func TestRequestToken_ReadBodyError(t *testing.T) {
	// Inject an HTTP response with a body that always fails on Read.
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errReadCloser{},
			Header:     make(http.Header),
		}, nil
	})
	c := NewClient(&http.Client{Transport: transport}, "", "http://token")
	_, err := c.requestToken(context.Background(), "client", "", "dev-code")
	if err == nil {
		t.Fatal("expected error for body read failure")
	}
	if !strings.Contains(err.Error(), "reading token response") {
		t.Errorf("expected 'reading token response' error, got %q", err.Error())
	}
}

func TestRequestDeviceCode_InvalidURL(t *testing.T) {
	c := NewClient(&http.Client{}, "://invalid-url", "")
	_, err := c.RequestDeviceCode(context.Background(), "client", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	t.Logf("got expected error: %v", err)
}

func TestRequestToken_InvalidURL(t *testing.T) {
	// Triggers the "creating token request" error in requestToken
	c := NewClient(&http.Client{}, "", "://invalid-url")
	_, err := c.requestToken(context.Background(), "client", "", "dev-code")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "creating token request") {
		t.Errorf("expected 'creating token request' error, got %q", err.Error())
	}
}

func TestRequestToken_NetworkError(t *testing.T) {
	// Use an unreachable endpoint to trigger "requesting token" error
	c := NewClient(&http.Client{Timeout: 100 * time.Millisecond}, "", "http://127.0.0.1:1/token")
	_, err := c.requestToken(context.Background(), "client", "", "dev-code")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "requesting token") {
		t.Errorf("expected 'requesting token' error, got %q", err.Error())
	}
}

func TestRequestToken_WithClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("client_secret") != "sec" {
			t.Errorf("expected client_secret=sec, got %q", r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{AccessToken: "tok"})
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), "", srv.URL)
	resp, err := c.requestToken(context.Background(), "client", "sec", "dev-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("expected AccessToken=tok, got %q", resp.AccessToken)
	}
}
