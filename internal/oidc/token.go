package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
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

type TokenValidator struct {
	JWKSEndpoint string
	HTTPClient   *http.Client
	cachedKeys   map[string]*rsa.PublicKey
}

func NewTokenValidator(jwksEndpoint string, httpClient *http.Client) *TokenValidator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &TokenValidator{
		JWKSEndpoint: jwksEndpoint,
		HTTPClient:   httpClient,
		cachedKeys:   make(map[string]*rsa.PublicKey),
	}
}

func (v *TokenValidator) FetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.JWKSEndpoint, nil)
	if err != nil {
		return fmt.Errorf("creating JWKS request: %w", err)
	}

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS response: %w", err)
	}

	var jwks JWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parsing JWKS response: %w", err)
	}

	v.cachedKeys = make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}
		pubKey, err := parseRSAPublicKey(key.N, key.E)
		if err != nil {
			continue
		}
		v.cachedKeys[key.Kid] = pubKey
	}

	return nil
}

func (v *TokenValidator) ValidateIDToken(ctx context.Context, rawToken string, expectedAudience string) (*Claims, error) {
	if len(v.cachedKeys) == 0 {
		if err := v.FetchJWKS(ctx); err != nil {
			return nil, fmt.Errorf("fetching JWKS for validation: %w", err)
		}
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		key, ok := v.cachedKeys[kid]
		if !ok {
			// Try refreshing JWKS once
			if err := v.FetchJWKS(ctx); err != nil {
				return nil, fmt.Errorf("refreshing JWKS: %w", err)
			}
			key, ok = v.cachedKeys[kid]
			if !ok {
				return nil, fmt.Errorf("unknown signing key ID: %s", kid)
			}
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing/validating token: %w", err)
	}

	// Defensive type assertion: jwt.Parser always returns jwt.MapClaims when
	// no custom claims struct is provided, so the !ok branch is unreachable in
	// practice. It remains as a safety guard against future jwt library changes.
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	claims := &Claims{}
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if aud, ok := mapClaims["aud"].(string); ok {
		claims.Audience = aud
	}
	// aud can also be an array
	if audArr, ok := mapClaims["aud"].([]interface{}); ok && len(audArr) > 0 {
		if audStr, ok := audArr[0].(string); ok {
			claims.Audience = audStr
		}
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if ev, ok := mapClaims["email_verified"].(bool); ok {
		claims.EmailVerified = ev
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.Expiry = int64(exp)
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	// Validate issuer
	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return nil, fmt.Errorf("invalid issuer: %q", claims.Issuer)
	}

	// Validate audience
	if claims.Audience != expectedAudience {
		return nil, fmt.Errorf("invalid audience: expected %q, got %q", expectedAudience, claims.Audience)
	}

	// Validate email_verified
	if !claims.EmailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("email claim is empty")
	}

	return claims, nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

