package pam

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type IOHandler struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	LogLevel string
}

func NewIOHandler(stdin io.Reader, stdout io.Writer, stderr io.Writer, logLevel string) *IOHandler {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if logLevel == "" {
		logLevel = "info"
	}
	return &IOHandler{
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
		LogLevel: strings.ToLower(logLevel),
	}
}

func (h *IOHandler) ReadUsername() (string, error) {
	// First check PAM_USER env var
	if user := os.Getenv("PAM_USER"); user != "" {
		return strings.TrimSpace(user), nil
	}
	// Fall back to reading from stdin
	scanner := bufio.NewScanner(h.Stdin)
	if scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username == "" {
			return "", fmt.Errorf("empty username received from stdin")
		}
		return username, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading username from stdin: %w", err)
	}
	return "", fmt.Errorf("no username available from environment or stdin")
}

func (h *IOHandler) DisplayMessage(msg string) error {
	_, err := fmt.Fprintln(h.Stdout, msg)
	return err
}

var logLevelOrder = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

func (h *IOHandler) shouldLog(level string) bool {
	return logLevelOrder[level] >= logLevelOrder[h.LogLevel]
}

func (h *IOHandler) LogDebug(msg string) {
	if h.shouldLog("debug") {
		fmt.Fprintf(h.Stderr, "[DEBUG] %s\n", msg)
	}
}

func (h *IOHandler) LogInfo(msg string) {
	if h.shouldLog("info") {
		fmt.Fprintf(h.Stderr, "[INFO] %s\n", msg)
	}
}

func (h *IOHandler) LogWarn(msg string) {
	if h.shouldLog("warn") {
		fmt.Fprintf(h.Stderr, "[WARN] %s\n", msg)
	}
}

func (h *IOHandler) LogError(msg string) {
	if h.shouldLog("error") {
		fmt.Fprintf(h.Stderr, "[ERROR] %s\n", msg)
	}
}
