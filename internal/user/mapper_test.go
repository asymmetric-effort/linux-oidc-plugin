package user

import (
	"strings"
	"testing"
)

func TestNewMapperLowercasesDomains(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"Example.COM", "TEST.Org"})
	if m.AllowedDomains[0] != "example.com" {
		t.Errorf("AllowedDomains[0] = %q, want %q", m.AllowedDomains[0], "example.com")
	}
	if m.AllowedDomains[1] != "test.org" {
		t.Errorf("AllowedDomains[1] = %q, want %q", m.AllowedDomains[1], "test.org")
	}
}

func TestEmailPrefixMapping(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	user, err := m.MapEmailToUser("user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("got %q, want %q", user, "user")
	}
}

func TestStaticMappingKnownEmail(t *testing.T) {
	mappings := map[string]string{
		"alice@example.com": "localalice",
	}
	m := NewMapper("static", mappings, []string{"example.com"})
	user, err := m.MapEmailToUser("alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "localalice" {
		t.Errorf("got %q, want %q", user, "localalice")
	}
}

func TestStaticMappingUnknownEmail(t *testing.T) {
	mappings := map[string]string{
		"alice@example.com": "localalice",
	}
	m := NewMapper("static", mappings, []string{"example.com"})
	_, err := m.MapEmailToUser("bob@example.com")
	if err == nil {
		t.Fatal("expected error for unknown email in static mapping")
	}
	if !strings.Contains(err.Error(), "no mapping found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAllowedDomainPasses(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	if !m.IsAllowedDomain("user@example.com") {
		t.Error("expected example.com to be allowed")
	}
}

func TestDisallowedDomainReturnsError(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("user@evil.com")
	if err == nil {
		t.Fatal("expected error for disallowed domain")
	}
	if !strings.Contains(err.Error(), "not in allowed domains") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsAllowedDomainDisallowed(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	if m.IsAllowedDomain("user@evil.com") {
		t.Error("expected evil.com to be disallowed")
	}
}

func TestEmptyEmailReturnsError(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("")
	if err == nil {
		t.Fatal("expected error for empty email")
	}
	if !strings.Contains(err.Error(), "email is empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWhitespaceOnlyEmailReturnsError(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only email")
	}
	if !strings.Contains(err.Error(), "email is empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMalformedEmailNoAt(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("userexample.com")
	if err == nil {
		t.Fatal("expected error for email without @")
	}
	if !strings.Contains(err.Error(), "invalid email format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMalformedEmailAtOnly(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("@")
	if err == nil {
		t.Fatal("expected error for @ only")
	}
	if !strings.Contains(err.Error(), "invalid email format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMalformedEmailNoLocalPart(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("@example.com")
	if err == nil {
		t.Fatal("expected error for missing local part")
	}
	if !strings.Contains(err.Error(), "invalid email format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMalformedEmailNoDomain(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("user@")
	if err == nil {
		t.Fatal("expected error for missing domain")
	}
	if !strings.Contains(err.Error(), "invalid email format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMultipleAllowedDomains(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com", "test.org", "corp.net"})

	tests := []struct {
		email string
		want  string
	}{
		{"alice@example.com", "alice"},
		{"bob@test.org", "bob"},
		{"carol@corp.net", "carol"},
	}
	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			got, err := m.MapEmailToUser(tc.email)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCaseInsensitivity(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	user, err := m.MapEmailToUser("User@Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("got %q, want %q", user, "user")
	}
}

func TestCaseInsensitivityIsAllowedDomain(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"Example.COM"})
	if !m.IsAllowedDomain("user@example.com") {
		t.Error("expected case-insensitive domain match")
	}
}

func TestUnknownMappingType(t *testing.T) {
	m := NewMapper("bogus", nil, []string{"example.com"})
	_, err := m.MapEmailToUser("user@example.com")
	if err == nil {
		t.Fatal("expected error for unknown mapping type")
	}
	if !strings.Contains(err.Error(), "unknown mapping type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEmailWithSpacesTrimmed(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	user, err := m.MapEmailToUser("  user@example.com  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("got %q, want %q", user, "user")
	}
}

func TestIsAllowedDomainNoAtSign(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	if m.IsAllowedDomain("noemailhere") {
		t.Error("expected false for string without @")
	}
}

func TestIsAllowedDomainWithSpaces(t *testing.T) {
	m := NewMapper("email_prefix", nil, []string{"example.com"})
	if !m.IsAllowedDomain("  user@example.com  ") {
		t.Error("expected IsAllowedDomain to trim spaces")
	}
}

func TestStaticMappingCaseInsensitive(t *testing.T) {
	// The mapper lowercases email before lookup, so mappings keys should be lowercase
	mappings := map[string]string{
		"alice@example.com": "localalice",
	}
	m := NewMapper("static", mappings, []string{"example.com"})
	user, err := m.MapEmailToUser("Alice@Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "localalice" {
		t.Errorf("got %q, want %q", user, "localalice")
	}
}

func TestNewMapperPreservesFields(t *testing.T) {
	mappings := map[string]string{"a@b.com": "x"}
	m := NewMapper("static", mappings, []string{"b.com"})
	if m.Type != "static" {
		t.Errorf("Type = %q, want %q", m.Type, "static")
	}
	if m.Mappings["a@b.com"] != "x" {
		t.Error("Mappings not preserved")
	}
	if len(m.AllowedDomains) != 1 || m.AllowedDomains[0] != "b.com" {
		t.Errorf("AllowedDomains = %v, want [b.com]", m.AllowedDomains)
	}
}
