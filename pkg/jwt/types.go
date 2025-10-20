package jwt

import "math/big"

// PublicKeyData holds the raw public key coordinates for serialization
type PublicKeyData struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}
