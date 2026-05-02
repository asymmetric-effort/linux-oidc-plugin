package user

import (
	"fmt"
	"strings"
)

type Mapper struct {
	Type           string
	Mappings       map[string]string
	AllowedDomains []string
}

func NewMapper(mappingType string, mappings map[string]string, allowedDomains []string) *Mapper {
	lower := make([]string, len(allowedDomains))
	for i, d := range allowedDomains {
		lower[i] = strings.ToLower(d)
	}
	return &Mapper{
		Type:           mappingType,
		Mappings:       mappings,
		AllowedDomains: lower,
	}
}

func (m *Mapper) MapEmailToUser(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", fmt.Errorf("email is empty")
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid email format: %q", email)
	}

	if !m.IsAllowedDomain(email) {
		return "", fmt.Errorf("domain %q is not in allowed domains", parts[1])
	}

	switch m.Type {
	case "email_prefix":
		return parts[0], nil
	case "static":
		username, ok := m.Mappings[email]
		if !ok {
			return "", fmt.Errorf("no mapping found for email %q", email)
		}
		return username, nil
	default:
		return "", fmt.Errorf("unknown mapping type: %q", m.Type)
	}
}

func (m *Mapper) IsAllowedDomain(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]
	for _, d := range m.AllowedDomains {
		if d == domain {
			return true
		}
	}
	return false
}
