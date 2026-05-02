package pam

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestReadUsername_FromEnv(t *testing.T) {
	t.Setenv("PAM_USER", "envuser")
	stdin := bytes.NewBufferString("stdinuser\n")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	username, err := h.ReadUsername()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "envuser" {
		t.Errorf("expected %q, got %q", "envuser", username)
	}
}

func TestReadUsername_FromStdin(t *testing.T) {
	t.Setenv("PAM_USER", "")
	stdin := bytes.NewBufferString("stdinuser\n")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	username, err := h.ReadUsername()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "stdinuser" {
		t.Errorf("expected %q, got %q", "stdinuser", username)
	}
}

func TestReadUsername_EmptyStdin(t *testing.T) {
	t.Setenv("PAM_USER", "")
	stdin := bytes.NewBufferString("   \n")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	_, err := h.ReadUsername()
	if err == nil {
		t.Fatal("expected error for empty stdin username")
	}
	if !strings.Contains(err.Error(), "empty username") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadUsername_NoInput(t *testing.T) {
	t.Setenv("PAM_USER", "")
	stdin := bytes.NewBufferString("")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	_, err := h.ReadUsername()
	if err == nil {
		t.Fatal("expected error for no input")
	}
	if !strings.Contains(err.Error(), "no username available") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadUsername_EnvPriority(t *testing.T) {
	t.Setenv("PAM_USER", "envuser")
	stdin := bytes.NewBufferString("stdinuser\n")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	username, err := h.ReadUsername()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "envuser" {
		t.Errorf("expected env user %q, got %q", "envuser", username)
	}
}

func TestReadUsername_Trimming(t *testing.T) {
	t.Setenv("PAM_USER", "")
	stdin := bytes.NewBufferString("  spaceduser  \n")
	h := NewIOHandler(stdin, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	username, err := h.ReadUsername()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "spaceduser" {
		t.Errorf("expected %q, got %q", "spaceduser", username)
	}
}

func TestReadUsername_EnvTrimming(t *testing.T) {
	t.Setenv("PAM_USER", "  envspaced  ")
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	username, err := h.ReadUsername()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "envspaced" {
		t.Errorf("expected %q, got %q", "envspaced", username)
	}
}

// errReader is an io.Reader that always returns an error
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

func TestReadUsername_StdinError(t *testing.T) {
	t.Setenv("PAM_USER", "")
	h := NewIOHandler(errReader{}, &bytes.Buffer{}, &bytes.Buffer{}, "info")

	_, err := h.ReadUsername()
	if err == nil {
		t.Fatal("expected error for stdin read failure")
	}
	if !strings.Contains(err.Error(), "reading username from stdin") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDisplayMessage(t *testing.T) {
	stdout := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, stdout, &bytes.Buffer{}, "info")

	err := h.DisplayMessage("hello world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := stdout.String(); got != "hello world\n" {
		t.Errorf("expected %q, got %q", "hello world\n", got)
	}
}

func TestLogDebug_DebugLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "debug")

	h.LogDebug("test debug message")
	if got := stderr.String(); got != "[DEBUG] test debug message\n" {
		t.Errorf("expected debug message, got %q", got)
	}
}

func TestLogDebug_InfoLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "info")

	h.LogDebug("test debug message")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogInfo_InfoLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "info")

	h.LogInfo("test info message")
	if got := stderr.String(); got != "[INFO] test info message\n" {
		t.Errorf("expected info message, got %q", got)
	}
}

func TestLogInfo_WarnLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "warn")

	h.LogInfo("test info message")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogWarn_WarnLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "warn")

	h.LogWarn("test warn message")
	if got := stderr.String(); got != "[WARN] test warn message\n" {
		t.Errorf("expected warn message, got %q", got)
	}
}

func TestLogWarn_ErrorLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "error")

	h.LogWarn("test warn message")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogError_Always(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, level)

			h.LogError("test error message")
			if got := stderr.String(); got != "[ERROR] test error message\n" {
				t.Errorf("at log level %s: expected error message, got %q", level, got)
			}
		})
	}
}

func TestNewIOHandler_Defaults(t *testing.T) {
	h := NewIOHandler(nil, nil, nil, "")

	if h.Stdin != os.Stdin {
		t.Error("expected Stdin to default to os.Stdin")
	}
	if h.Stdout != os.Stdout {
		t.Error("expected Stdout to default to os.Stdout")
	}
	if h.Stderr != os.Stderr {
		t.Error("expected Stderr to default to os.Stderr")
	}
	if h.LogLevel != "info" {
		t.Errorf("expected LogLevel %q, got %q", "info", h.LogLevel)
	}
}

func TestNewIOHandler_EmptyLogLevel(t *testing.T) {
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, "")

	if h.LogLevel != "info" {
		t.Errorf("expected LogLevel %q, got %q", "info", h.LogLevel)
	}
}

func TestNewIOHandler_LogLevelCaseInsensitive(t *testing.T) {
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, "DEBUG")

	if h.LogLevel != "debug" {
		t.Errorf("expected LogLevel %q, got %q", "debug", h.LogLevel)
	}
}

func TestNewIOHandler_CustomStreams(t *testing.T) {
	stdin := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	h := NewIOHandler(stdin, stdout, stderr, "warn")

	if h.Stdin != stdin {
		t.Error("expected custom Stdin")
	}
	if h.Stdout != stdout {
		t.Error("expected custom Stdout")
	}
	if h.Stderr != stderr {
		t.Error("expected custom Stderr")
	}
	if h.LogLevel != "warn" {
		t.Errorf("expected LogLevel %q, got %q", "warn", h.LogLevel)
	}
}

func TestLogDebug_WarnLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "warn")

	h.LogDebug("should not appear")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogDebug_ErrorLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "error")

	h.LogDebug("should not appear")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogInfo_DebugLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "debug")

	h.LogInfo("visible at debug level")
	if got := stderr.String(); !strings.Contains(got, "[INFO]") {
		t.Errorf("expected info message at debug level, got %q", got)
	}
}

func TestLogInfo_ErrorLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "error")

	h.LogInfo("should not appear")
	if got := stderr.String(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
}

func TestLogWarn_DebugLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "debug")

	h.LogWarn("visible at debug level")
	if got := stderr.String(); !strings.Contains(got, "[WARN]") {
		t.Errorf("expected warn message at debug level, got %q", got)
	}
}

func TestLogWarn_InfoLevel(t *testing.T) {
	stderr := &bytes.Buffer{}
	h := NewIOHandler(&bytes.Buffer{}, &bytes.Buffer{}, stderr, "info")

	h.LogWarn("visible at info level")
	if got := stderr.String(); !strings.Contains(got, "[WARN]") {
		t.Errorf("expected warn message at info level, got %q", got)
	}
}
