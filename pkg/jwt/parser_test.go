package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndParseJWT(t *testing.T) {
	// Generate test key and JWT
	fixture := MustGenerateTestFixture(nil)

	// Parse the JWT
	parsed, err := Parse(fixture.JWT)
	require.NoError(t, err, "Failed to parse JWT")

	// Verify signature components exist
	assert.NotNil(t, parsed.SignatureR, "SignatureR should not be nil")
	assert.NotNil(t, parsed.SignatureS, "SignatureS should not be nil")

	// Verify message hash
	assert.NotEqual(t, [32]byte{}, parsed.MessageHash, "MessageHash should not be empty")

	// Set public key and verify
	parsed.SetPublicKey(fixture.PublicKey)
	err = parsed.Verify()
	assert.NoError(t, err, "Signature verification should succeed")
}

func TestParseInvalidJWT(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"only header", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"two parts", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0"},
		{"invalid base64", "invalid.invalid.invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.token)
			assert.Error(t, err, "Should fail to parse invalid JWT")
		})
	}
}

func TestParseWithPublicKey(t *testing.T) {
	// Generate valid JWT
	fixture := MustGenerateTestFixture(map[string]interface{}{
		"sub":  "test-user",
		"name": "Test User",
	})

	// Parse with correct public key
	parsed, err := ParseWithPublicKey(fixture.JWT, fixture.PublicKey)
	require.NoError(t, err, "Should parse with valid public key")
	assert.Equal(t, "test-user", parsed.Claims["sub"])

	// Generate different key
	wrongKey, err := GenerateTestKey()
	require.NoError(t, err)

	// Parse with wrong public key should fail
	_, err = ParseWithPublicKey(fixture.JWT, &wrongKey.PublicKey)
	assert.Error(t, err, "Should fail with wrong public key")
}

func TestSignatureExtraction(t *testing.T) {
	fixture := MustGenerateTestFixture(nil)
	parsed := MustParse(t, fixture.JWT)

	// Verify signature components are 256-bit values (for P-256)
	assert.True(t, parsed.SignatureR.BitLen() <= 256, "R should be <= 256 bits")
	assert.True(t, parsed.SignatureS.BitLen() <= 256, "S should be <= 256 bits")

	// Verify they're not zero
	assert.True(t, parsed.SignatureR.Sign() > 0, "R should be positive")
	assert.True(t, parsed.SignatureS.Sign() > 0, "S should be positive")
}

func TestMessageHashing(t *testing.T) {
	fixture := MustGenerateTestFixture(map[string]interface{}{
		"data": "test",
	})

	parsed := MustParse(t, fixture.JWT)

	// Verify message hash is SHA-256 (32 bytes)
	assert.Len(t, parsed.MessageHash, 32, "Message hash should be 32 bytes")

	// Verify message format is header.payload
	expectedMessage := parsed.Header + "." + parsed.Payload
	assert.Equal(t, expectedMessage, string(parsed.Message))
}

// Helper function for tests
func MustParse(t *testing.T, token string) *ParsedJWT {
	parsed, err := Parse(token)
	require.NoError(t, err)
	return parsed
}
