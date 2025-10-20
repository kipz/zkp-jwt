package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ParsedJWT contains the extracted components of a JWT needed for ZK proof generation
type ParsedJWT struct {
	// Original token string
	Token string

	// Header and payload (the message that was signed)
	Header  string
	Payload string
	Message []byte // base64url(header) + "." + base64url(payload)

	// Message hash (SHA-256)
	MessageHash [32]byte

	// ECDSA signature components
	SignatureR *big.Int
	SignatureS *big.Int

	// Public key used to verify the signature
	PublicKey *ecdsa.PublicKey

	// Claims (decoded payload)
	Claims jwt.MapClaims
}

// Parse extracts all necessary components from a JWT string for ZK proof generation
func Parse(tokenString string) (*ParsedJWT, error) {
	// Split JWT into parts: header.payload.signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}

	header := parts[0]
	payload := parts[1]
	signatureB64 := parts[2]

	// Decode and parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	// Verify algorithm is ES256
	alg, ok := headerMap["alg"].(string)
	if !ok || alg != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (only ES256 is supported)", alg)
	}

	// Decode payload (claims)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims jwt.MapClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	// Extract signature (r, s components)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	r, s, err := parseECDSASignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	// Build the message that was signed (header.payload)
	message := []byte(header + "." + payload)
	messageHash := sha256.Sum256(message)

	return &ParsedJWT{
		Token:       tokenString,
		Header:      header,
		Payload:     payload,
		Message:     message,
		MessageHash: messageHash,
		SignatureR:  r,
		SignatureS:  s,
		Claims:      claims,
		// PublicKey will be set separately when loaded from external source
	}, nil
}

// ParseWithPublicKey parses a JWT and verifies it with the provided public key
func ParseWithPublicKey(tokenString string, publicKey *ecdsa.PublicKey) (*ParsedJWT, error) {
	parsed, err := Parse(tokenString)
	if err != nil {
		return nil, err
	}

	parsed.PublicKey = publicKey

	// Verify the signature
	if !ecdsa.Verify(publicKey, parsed.MessageHash[:], parsed.SignatureR, parsed.SignatureS) {
		return nil, errors.New("signature verification failed")
	}

	return parsed, nil
}

// parseECDSASignature extracts r and s from DER or raw ECDSA signature bytes
// ES256 signatures in JWT are 64 bytes: 32 bytes R + 32 bytes S (raw format)
func parseECDSASignature(sigBytes []byte) (*big.Int, *big.Int, error) {
	// ES256 uses raw format: R (32 bytes) || S (32 bytes)
	if len(sigBytes) != 64 {
		return nil, nil, fmt.Errorf("invalid ES256 signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	return r, s, nil
}

// SetPublicKey sets the public key for a parsed JWT
func (p *ParsedJWT) SetPublicKey(publicKey *ecdsa.PublicKey) {
	p.PublicKey = publicKey
}

// Verify checks if the JWT signature is valid using the stored public key
func (p *ParsedJWT) Verify() error {
	if p.PublicKey == nil {
		return errors.New("public key not set")
	}

	if !ecdsa.Verify(p.PublicKey, p.MessageHash[:], p.SignatureR, p.SignatureS) {
		return errors.New("signature verification failed")
	}

	return nil
}
