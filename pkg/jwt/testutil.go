package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// GenerateTestKey generates a new P-256 ECDSA key pair for testing
func GenerateTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateTestJWT creates a test JWT with the given claims and signs it with the private key
func GenerateTestJWT(privateKey *ecdsa.PrivateKey, claims map[string]interface{}) (string, error) {
	// Default claims if not provided
	if claims == nil {
		claims = map[string]interface{}{
			"sub":   "1234567890",
			"name":  "Test User",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
			"iss":   "test-issuer",
			"aud":   "test-audience",
			"email": "test@example.com",
		}
	}

	// Create header
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create message to sign
	message := headerB64 + "." + payloadB64
	messageHash := sha256.Sum256([]byte(message))

	// Sign with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, messageHash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Encode signature (R || S, each 32 bytes)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad with leading zeros if necessary
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Construct JWT
	jwt := message + "." + signatureB64

	return jwt, nil
}

// TestFixture contains a JWT and its associated key pair for testing
type TestFixture struct {
	JWT        string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Claims     map[string]interface{}
}

// GenerateTestFixture creates a complete test fixture with a key pair and signed JWT
func GenerateTestFixture(claims map[string]interface{}) (*TestFixture, error) {
	privateKey, err := GenerateTestKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	jwt, err := GenerateTestJWT(privateKey, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	return &TestFixture{
		JWT:        jwt,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Claims:     claims,
	}, nil
}

// MustGenerateTestFixture is like GenerateTestFixture but panics on error (useful in tests)
func MustGenerateTestFixture(claims map[string]interface{}) *TestFixture {
	fixture, err := GenerateTestFixture(claims)
	if err != nil {
		panic(err)
	}
	return fixture
}

// HashMessage computes SHA-256 hash of a message
func HashMessage(message []byte) [32]byte {
	return sha256.Sum256(message)
}

// SignMessage signs a message hash with an ECDSA private key
func SignMessage(privateKey *ecdsa.PrivateKey, messageHash [32]byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(rand.Reader, privateKey, messageHash[:])
}

// VerifySignature verifies an ECDSA signature
func VerifySignature(publicKey *ecdsa.PublicKey, messageHash [32]byte, r, s *big.Int) bool {
	return ecdsa.Verify(publicKey, messageHash[:], r, s)
}
