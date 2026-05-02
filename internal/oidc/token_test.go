package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKeyPair holds a generated RSA key pair for testing.
var testKey *rsa.PrivateKey

func init() {
	var err error
	testKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
}

const testKid = "test-key-1"

// createTestJWT creates a signed JWT with the given claims and kid.
func createTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing test JWT: %v", err)
	}
	return signed
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK for serving in JWKS.
func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kid: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// serveJWKS creates an httptest server that serves a JWKS response containing the given keys.
func serveJWKS(t *testing.T, keys ...JWK) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(JWKSResponse{Keys: keys})
	}))
}

// validClaims returns a set of standard valid claims for testing.
func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":            "accounts.google.com",
		"sub":            "user-123",
		"aud":            "my-audience",
		"email":          "user@example.com",
		"email_verified": true,
		"exp":            float64(now.Add(1 * time.Hour).Unix()),
		"iat":            float64(now.Unix()),
	}
}

func TestNewTokenValidator_NilHTTPClient(t *testing.T) {
	v := NewTokenValidator("http://jwks", nil)
	if v.HTTPClient == nil {
		t.Fatal("expected non-nil HTTPClient")
	}
	if v.JWKSEndpoint != "http://jwks" {
		t.Fatalf("expected JWKSEndpoint=%q, got %q", "http://jwks", v.JWKSEndpoint)
	}
	if v.cachedKeys == nil {
		t.Fatal("expected non-nil cachedKeys map")
	}
}

func TestFetchJWKS_Success(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.cachedKeys) != 1 {
		t.Fatalf("expected 1 cached key, got %d", len(v.cachedKeys))
	}
	if _, ok := v.cachedKeys[testKid]; !ok {
		t.Errorf("expected key with kid=%q in cache", testKid)
	}
}

func TestFetchJWKS_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected status 500 error, got %q", err.Error())
	}
}

func TestFetchJWKS_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing JWKS response") {
		t.Errorf("expected parsing error, got %q", err.Error())
	}
}

func TestFetchJWKS_SkipsNonRSAKeys(t *testing.T) {
	rsaKey := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	ecKey := JWK{
		Kid: "ec-key",
		Kty: "EC",
		Alg: "ES256",
		Use: "sig",
	}
	nonSigKey := JWK{
		Kid: "enc-key",
		Kty: "RSA",
		Alg: "RS256",
		Use: "enc", // not "sig"
		N:   rsaKey.N,
		E:   rsaKey.E,
	}
	srv := serveJWKS(t, rsaKey, ecKey, nonSigKey)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.cachedKeys) != 1 {
		t.Fatalf("expected 1 cached key (EC and enc should be skipped), got %d", len(v.cachedKeys))
	}
	if _, ok := v.cachedKeys[testKid]; !ok {
		t.Error("expected RSA sig key to be cached")
	}
}

func TestFetchJWKS_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetchJWKS_InvalidKeyData(t *testing.T) {
	// Key with bad base64 in N - should be skipped without error
	badKey := JWK{
		Kid: "bad-key",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   "!!!invalid-base64!!!",
		E:   "AQAB",
	}
	srv := serveJWKS(t, badKey)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	err := v.FetchJWKS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.cachedKeys) != 0 {
		t.Errorf("expected 0 cached keys (bad key should be skipped), got %d", len(v.cachedKeys))
	}
}

func TestValidateIDToken_Success(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	token := createTestJWT(t, testKey, testKid, validClaims())
	claims, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Issuer != "accounts.google.com" {
		t.Errorf("expected iss=accounts.google.com, got %q", claims.Issuer)
	}
	if claims.Subject != "user-123" {
		t.Errorf("expected sub=user-123, got %q", claims.Subject)
	}
	if claims.Audience != "my-audience" {
		t.Errorf("expected aud=my-audience, got %q", claims.Audience)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Error("expected email_verified=true")
	}
	if claims.Expiry == 0 {
		t.Error("expected non-zero expiry")
	}
	if claims.IssuedAt == 0 {
		t.Error("expected non-zero issued_at")
	}
}

func TestValidateIDToken_ExpiredToken(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["exp"] = float64(time.Now().Add(-1 * time.Hour).Unix())

	token := createTestJWT(t, testKey, testKid, claims)
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("expected token expired error, got %q", err.Error())
	}
}

func TestValidateIDToken_WrongAudience(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["aud"] = "wrong-audience"

	token := createTestJWT(t, testKey, testKid, claims)
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Errorf("expected audience error, got %q", err.Error())
	}
}

func TestValidateIDToken_WrongIssuer(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["iss"] = "https://evil.com"

	token := createTestJWT(t, testKey, testKid, claims)
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
	if !strings.Contains(err.Error(), "invalid issuer") {
		t.Errorf("expected issuer error, got %q", err.Error())
	}
}

func TestValidateIDToken_GoogleHTTPSIssuer(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["iss"] = "https://accounts.google.com"

	token := createTestJWT(t, testKey, testKid, claims)
	result, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err != nil {
		t.Fatalf("unexpected error for https issuer: %v", err)
	}
	if result.Issuer != "https://accounts.google.com" {
		t.Errorf("expected iss=https://accounts.google.com, got %q", result.Issuer)
	}
}

func TestValidateIDToken_EmailNotVerified(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["email_verified"] = false

	token := createTestJWT(t, testKey, testKid, claims)
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for unverified email, got nil")
	}
	if !strings.Contains(err.Error(), "email not verified") {
		t.Errorf("expected email not verified error, got %q", err.Error())
	}
}

func TestValidateIDToken_EmptyEmail(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	claims["email"] = ""
	claims["email_verified"] = true

	token := createTestJWT(t, testKey, testKid, claims)
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for empty email, got nil")
	}
	if !strings.Contains(err.Error(), "email claim is empty") {
		t.Errorf("expected empty email error, got %q", err.Error())
	}
}

func TestValidateIDToken_InvalidSignature(t *testing.T) {
	// Sign with a different key than what's in JWKS
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating other key: %v", err)
	}

	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	// Sign with otherKey but use kid that maps to testKey
	token := createTestJWT(t, otherKey, testKid, validClaims())
	_, err = v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	if !strings.Contains(err.Error(), "parsing/validating token") {
		t.Errorf("expected parsing/validating error, got %q", err.Error())
	}
}

func TestValidateIDToken_MalformedToken(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	_, err := v.ValidateIDToken(context.Background(), "this-is-not-a-jwt", "my-audience")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
	if !strings.Contains(err.Error(), "parsing/validating token") {
		t.Errorf("expected parsing error, got %q", err.Error())
	}
}

func TestValidateIDToken_UnknownKid(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	// Use a kid that doesn't match any key in JWKS
	token := createTestJWT(t, testKey, "unknown-kid", validClaims())
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
	if !strings.Contains(err.Error(), "unknown signing key ID") {
		t.Errorf("expected unknown key ID error, got %q", err.Error())
	}
}

func TestValidateIDToken_FetchesJWKSIfEmpty(t *testing.T) {
	var fetchCount atomic.Int32
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(JWKSResponse{Keys: []JWK{jwk}})
	}))
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	// Don't pre-fetch JWKS - cachedKeys is empty

	token := createTestJWT(t, testKey, testKid, validClaims())
	claims, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %q", claims.Email)
	}
	if fetchCount.Load() < 1 {
		t.Error("expected JWKS to be auto-fetched at least once")
	}
}

func TestValidateIDToken_RefreshesJWKSOnUnknownKid(t *testing.T) {
	// Generate a second key that will only appear on the second JWKS fetch
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating second key: %v", err)
	}
	secondKid := "test-key-2"

	var fetchCount atomic.Int32
	jwk1 := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	jwk2 := rsaPublicKeyToJWK(&secondKey.PublicKey, secondKid)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// First fetch: only has key 1
			json.NewEncoder(w).Encode(JWKSResponse{Keys: []JWK{jwk1}})
		} else {
			// Subsequent fetches: has both keys
			json.NewEncoder(w).Encode(JWKSResponse{Keys: []JWK{jwk1, jwk2}})
		}
	}))
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	// Pre-fetch to get only key 1
	if err := v.FetchJWKS(context.Background()); err != nil {
		t.Fatalf("pre-fetching JWKS: %v", err)
	}

	// Now validate a token signed with key 2 - should trigger JWKS refresh
	token := createTestJWT(t, secondKey, secondKid, validClaims())
	claims, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %q", claims.Email)
	}
	if fetchCount.Load() < 2 {
		t.Errorf("expected at least 2 JWKS fetches, got %d", fetchCount.Load())
	}
}

func TestValidateIDToken_AudienceArray(t *testing.T) {
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	claims := validClaims()
	// Set aud as an array
	claims["aud"] = []string{"my-audience", "other-audience"}

	token := createTestJWT(t, testKey, testKid, claims)
	result, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Audience != "my-audience" {
		t.Errorf("expected aud=my-audience, got %q", result.Audience)
	}
}

func TestParseRSAPublicKey_InvalidModulus(t *testing.T) {
	_, err := parseRSAPublicKey("!!!not-base64!!!", "AQAB")
	if err == nil {
		t.Fatal("expected error for invalid modulus")
	}
	if !strings.Contains(err.Error(), "decoding modulus") {
		t.Errorf("expected modulus decoding error, got %q", err.Error())
	}
}

func TestParseRSAPublicKey_InvalidExponent(t *testing.T) {
	// Valid base64 for N, invalid for E
	validN := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	_, err := parseRSAPublicKey(validN, "!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid exponent")
	}
	if !strings.Contains(err.Error(), "decoding exponent") {
		t.Errorf("expected exponent decoding error, got %q", err.Error())
	}
}

func TestParseRSAPublicKey_Success(t *testing.T) {
	n := base64.RawURLEncoding.EncodeToString(testKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(testKey.PublicKey.E)).Bytes())

	pub, err := parseRSAPublicKey(n, e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub.N.Cmp(testKey.PublicKey.N) != 0 {
		t.Error("parsed modulus does not match")
	}
	if pub.E != testKey.PublicKey.E {
		t.Errorf("parsed exponent %d does not match expected %d", pub.E, testKey.PublicKey.E)
	}
}

func TestValidateIDToken_FetchJWKSFailsOnEmpty(t *testing.T) {
	// JWKS endpoint is unreachable
	v := NewTokenValidator("http://127.0.0.1:1", &http.Client{Timeout: 100 * time.Millisecond})

	token := createTestJWT(t, testKey, testKid, validClaims())
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error when JWKS endpoint is unreachable")
	}
	if !strings.Contains(err.Error(), "fetching JWKS for validation") {
		t.Errorf("expected JWKS fetch error, got %q", err.Error())
	}
}

func TestFetchJWKS_InvalidURL(t *testing.T) {
	// Triggers the "creating JWKS request" error path
	v := NewTokenValidator("://invalid-url", &http.Client{})
	err := v.FetchJWKS(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "creating JWKS request") {
		t.Errorf("expected 'creating JWKS request' error, got %q", err.Error())
	}
}

func TestValidateIDToken_MissingKid(t *testing.T) {
	// Create a JWT without a kid header to hit the "missing kid" path
	jwk := rsaPublicKeyToJWK(&testKey.PublicKey, testKid)
	srv := serveJWKS(t, jwk)
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())

	// Create token without kid
	claims := validClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Deliberately do NOT set token.Header["kid"]
	signed, err := token.SignedString(testKey)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	_, err = v.ValidateIDToken(context.Background(), signed, "my-audience")
	if err == nil {
		t.Fatal("expected error for missing kid")
	}
	if !strings.Contains(err.Error(), "missing kid") {
		t.Errorf("expected 'missing kid' error, got %q", err.Error())
	}
}

func TestValidateIDToken_RefreshJWKSFails(t *testing.T) {
	// First serve valid JWKS, then fail on refresh
	var fetchCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		if n == 1 {
			// First fetch: return a key with a different kid
			jwk := rsaPublicKeyToJWK(&testKey.PublicKey, "other-kid")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(JWKSResponse{Keys: []JWK{jwk}})
		} else {
			// Subsequent fetches: fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	v := NewTokenValidator(srv.URL, srv.Client())
	if err := v.FetchJWKS(context.Background()); err != nil {
		t.Fatalf("pre-fetching JWKS: %v", err)
	}

	// Token with unknown kid -> triggers refresh -> refresh fails
	token := createTestJWT(t, testKey, testKid, validClaims())
	_, err := v.ValidateIDToken(context.Background(), token, "my-audience")
	if err == nil {
		t.Fatal("expected error when JWKS refresh fails")
	}
	if !strings.Contains(err.Error(), "refreshing JWKS") {
		t.Errorf("expected refreshing JWKS error, got %q", err.Error())
	}
}
