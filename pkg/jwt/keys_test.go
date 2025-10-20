package jwt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyToJWKAndBack(t *testing.T) {
	// Generate test key
	privKey, err := GenerateTestKey()
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// Convert to JWK
	jwk, err := PublicKeyToJWK(pubKey, "test-kid")
	require.NoError(t, err)
	assert.Equal(t, "EC", jwk.Kty)
	assert.Equal(t, "P-256", jwk.Crv)
	assert.Equal(t, "test-kid", jwk.Kid)

	// Convert back to public key
	recoveredKey, err := JWKToPublicKey(jwk)
	require.NoError(t, err)

	// Verify keys match
	assert.Equal(t, pubKey.X, recoveredKey.X)
	assert.Equal(t, pubKey.Y, recoveredKey.Y)
}

func TestLoadSavePublicKeyPEM(t *testing.T) {
	// Generate test key
	privKey, err := GenerateTestKey()
	require.NoError(t, err)

	// Create temp file
	tmpFile, err := os.CreateTemp("", "pubkey-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	err = pem.Encode(tmpFile, pemBlock)
	require.NoError(t, err)
	tmpFile.Close()

	// Load from file
	loadedKey, err := LoadPublicKeyFromPEM(tmpFile.Name())
	require.NoError(t, err)

	// Verify keys match
	assert.Equal(t, privKey.PublicKey.X, loadedKey.X)
	assert.Equal(t, privKey.PublicKey.Y, loadedKey.Y)
}

func TestLoadSavePublicKeyJWK(t *testing.T) {
	// Generate test key
	privKey, err := GenerateTestKey()
	require.NoError(t, err)

	// Convert to JWK
	jwk, err := PublicKeyToJWK(&privKey.PublicKey, "test-123")
	require.NoError(t, err)

	// Create temp file
	tmpFile, err := os.CreateTemp("", "pubkey-*.jwk")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write JWK to file
	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(jwk)
	require.NoError(t, err)
	tmpFile.Close()

	// Load from file
	loadedKey, err := LoadPublicKeyFromJWK(tmpFile.Name())
	require.NoError(t, err)

	// Verify keys match
	assert.Equal(t, privKey.PublicKey.X, loadedKey.X)
	assert.Equal(t, privKey.PublicKey.Y, loadedKey.Y)
}

func TestJWKSetLoading(t *testing.T) {
	// Generate multiple keys
	key1, _ := GenerateTestKey()
	key2, _ := GenerateTestKey()

	jwk1, _ := PublicKeyToJWK(&key1.PublicKey, "key-1")
	jwk2, _ := PublicKeyToJWK(&key2.PublicKey, "key-2")

	jwks := JWKSet{
		Keys: []JWK{*jwk1, *jwk2},
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "jwks-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write JWKS
	encoder := json.NewEncoder(tmpFile)
	err = encoder.Encode(jwks)
	require.NoError(t, err)
	tmpFile.Close()

	// Load specific key by kid
	loadedKey1, err := LoadPublicKeyFromJWKSet(tmpFile.Name(), "key-1")
	require.NoError(t, err)
	assert.Equal(t, key1.PublicKey.X, loadedKey1.X)

	loadedKey2, err := LoadPublicKeyFromJWKSet(tmpFile.Name(), "key-2")
	require.NoError(t, err)
	assert.Equal(t, key2.PublicKey.X, loadedKey2.X)

	// Load without kid (should get first key)
	firstKey, err := LoadPublicKeyFromJWKSet(tmpFile.Name(), "")
	require.NoError(t, err)
	assert.Equal(t, key1.PublicKey.X, firstKey.X)
}
