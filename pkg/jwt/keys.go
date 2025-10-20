package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// JWK represents a JSON Web Key for ECDSA P-256 keys
type JWK struct {
	Kty string `json:"kty"`           // Key Type (should be "EC")
	Crv string `json:"crv"`           // Curve (should be "P-256")
	X   string `json:"x"`             // X coordinate (base64url encoded)
	Y   string `json:"y"`             // Y coordinate (base64url encoded)
	D   string `json:"d,omitempty"`   // Private key (if present)
	Use string `json:"use,omitempty"` // Public Key Use
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm (should be "ES256")
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// LoadPublicKeyFromPEM loads an ECDSA public key from a PEM file
func LoadPublicKeyFromPEM(filename string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}

	return ParsePublicKeyFromPEM(data)
}

// ParsePublicKeyFromPEM parses an ECDSA public key from PEM-encoded bytes
func ParsePublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try parsing as PKIX public key
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	// Verify it's P-256
	if pubKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (only P-256 is supported)", pubKey.Curve.Params().Name)
	}

	return pubKey, nil
}

// LoadPrivateKeyFromPEM loads an ECDSA private key from a PEM file
func LoadPrivateKeyFromPEM(filename string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}

	return ParsePrivateKeyFromPEM(data)
}

// ParsePrivateKeyFromPEM parses an ECDSA private key from PEM-encoded bytes
func ParsePrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try parsing as EC private key
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		keyInterface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key (EC: %v, PKCS8: %v)", err, err2)
		}
		var ok bool
		privKey, ok = keyInterface.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
	}

	// Verify it's P-256
	if privKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (only P-256 is supported)", privKey.Curve.Params().Name)
	}

	return privKey, nil
}

// LoadPublicKeyFromJWK loads an ECDSA public key from a JWK JSON file
func LoadPublicKeyFromJWK(filename string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK file: %w", err)
	}

	return ParsePublicKeyFromJWK(data)
}

// ParsePublicKeyFromJWK parses an ECDSA public key from JWK JSON bytes
func ParsePublicKeyFromJWK(jwkData []byte) (*ecdsa.PublicKey, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK JSON: %w", err)
	}

	return JWKToPublicKey(&jwk)
}

// LoadPublicKeyFromJWKSet loads an ECDSA public key from a JWKS (JWK Set) file
// If kid is empty, returns the first key in the set
func LoadPublicKeyFromJWKSet(filename string, kid string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS file: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, errors.New("no keys found in JWKS")
	}

	// If no kid specified, use first key
	if kid == "" {
		return JWKToPublicKey(&jwks.Keys[0])
	}

	// Find key by kid
	for _, jwk := range jwks.Keys {
		if jwk.Kid == kid {
			return JWKToPublicKey(&jwk)
		}
	}

	return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
}

// JWKToPublicKey converts a JWK to an ECDSA public key
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s (expected EC)", jwk.Kty)
	}

	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (expected P-256)", jwk.Crv)
	}

	// Decode X and Y coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Create public key using P-256 curve
	pubKey := &ecdsa.PublicKey{
		Curve: getP256Curve(),
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

// PublicKeyToJWK converts an ECDSA public key to JWK format
func PublicKeyToJWK(pubKey *ecdsa.PublicKey, kid string) (*JWK, error) {
	if pubKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s (only P-256 supported)", pubKey.Curve.Params().Name)
	}

	// Encode coordinates to base64url
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Ensure 32-byte length (pad with leading zeros if necessary)
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Use: "sig",
		Alg: "ES256",
	}

	if kid != "" {
		jwk.Kid = kid
	}

	return jwk, nil
}

// getP256Curve returns the P-256 elliptic curve
// This is a helper to ensure we're using the correct curve
func getP256Curve() elliptic.Curve {
	return elliptic.P256()
}
