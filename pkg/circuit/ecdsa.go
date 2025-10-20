package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// P256Fp is the base field of P-256 (secp256r1)
type P256Fp = emulated.P256Fp

// P256Fr is the scalar field of P-256
type P256Fr = emulated.P256Fr

// ECDSASignature represents an ECDSA signature in the circuit
type ECDSASignature struct {
	R emulated.Element[P256Fr]
	S emulated.Element[P256Fr]
}

// ECDSAPublicKey represents an ECDSA public key point in the circuit
type ECDSAPublicKey = sw_emulated.AffinePoint[P256Fp]

// SingleECDSACircuit verifies a single P-256 ECDSA signature
// This circuit proves possession of a valid signature without revealing it
type SingleECDSACircuit struct {
	// Public inputs
	PublicKey   ECDSAPublicKey
	MessageHash emulated.Element[P256Fr]

	// Private inputs (witness)
	Signature ECDSASignature `gnark:",secret"`
}

// Define implements the gnark circuit interface
// It defines the constraints for ECDSA signature verification
func (c *SingleECDSACircuit) Define(api frontend.API) error {
	// Get P-256 curve parameters
	params := sw_emulated.GetP256Params()

	// Convert public key to ECDSA public key type
	publicKey := ecdsa.PublicKey[P256Fp, P256Fr](c.PublicKey)

	// Convert signature to ECDSA signature type
	signature := &ecdsa.Signature[P256Fr]{
		R: c.Signature.R,
		S: c.Signature.S,
	}

	// Verify the ECDSA signature
	// This performs the full ECDSA verification algorithm:
	// 1. Compute s_inv = s^-1 mod n
	// 2. Compute u1 = H(m) * s_inv mod n
	// 3. Compute u2 = r * s_inv mod n
	// 4. Compute R' = u1*G + u2*PublicKey
	// 5. Verify that R'.x mod n == r mod n
	publicKey.Verify(api, params, &c.MessageHash, signature)

	return nil
}

// BatchECDSACircuit verifies multiple P-256 ECDSA signatures in one proof
// This allows proving possession of multiple JWTs efficiently
type BatchECDSACircuit struct {
	// Number of signatures to verify
	BatchSize int

	// Public inputs (arrays of size BatchSize)
	PublicKeys    []ECDSAPublicKey
	MessageHashes []emulated.Element[P256Fr]

	// Private inputs (witness) - arrays of size BatchSize
	Signatures []ECDSASignature `gnark:",secret"`
}

// NewBatchECDSACircuit creates a new batch circuit for the given batch size
func NewBatchECDSACircuit(batchSize int) *BatchECDSACircuit {
	return &BatchECDSACircuit{
		BatchSize:     batchSize,
		PublicKeys:    make([]ECDSAPublicKey, batchSize),
		MessageHashes: make([]emulated.Element[P256Fr], batchSize),
		Signatures:    make([]ECDSASignature, batchSize),
	}
}

// Define implements the gnark circuit interface for batch verification
// It verifies all signatures in parallel
func (c *BatchECDSACircuit) Define(api frontend.API) error {
	// Get P-256 curve parameters
	params := sw_emulated.GetP256Params()

	// Verify each signature in the batch
	// All must be valid for the circuit to be satisfiable
	for i := 0; i < c.BatchSize; i++ {
		// Convert public key to ECDSA public key type
		publicKey := ecdsa.PublicKey[P256Fp, P256Fr](c.PublicKeys[i])

		// Convert signature to ECDSA signature type
		signature := &ecdsa.Signature[P256Fr]{
			R: c.Signatures[i].R,
			S: c.Signatures[i].S,
		}

		// Verify the ECDSA signature
		// This performs the full ECDSA verification algorithm:
		// 1. Compute s_inv = s^-1 mod n
		// 2. Compute u1 = H(m) * s_inv mod n
		// 3. Compute u2 = r * s_inv mod n
		// 4. Compute R' = u1*G + u2*PublicKey
		// 5. Verify that R'.x mod n == r mod n
		publicKey.Verify(api, params, &c.MessageHashes[i], signature)
	}

	return nil
}
