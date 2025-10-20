package prover

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/zkp-jwt/pkg/circuit"
	"github.com/zkp-jwt/pkg/jwt"
)

// Proof represents a ZK proof for JWT possession
type Proof struct {
	// The actual PLONK proof
	PlonkProof plonk.Proof

	// Public inputs that the verifier needs
	PublicInputs *PublicInputs

	// Constraint system (needed for verification)
	ConstraintSystem constraint.ConstraintSystem
}

// PublicInputs contains the public data needed for verification
type PublicInputs struct {
	// Public keys (one per JWT)
	PublicKeys []*jwt.PublicKeyData

	// Message hashes (one per JWT) - optional, can be used to bind proof to specific messages
	MessageHashes [][32]byte
}

// Prove generates a zero-knowledge proof for one or more JWTs
// The proof demonstrates possession of valid signatures without revealing them
func Prove(jwts []*jwt.ParsedJWT, provingKey plonk.ProvingKey) (*Proof, error) {
	if len(jwts) == 0 {
		return nil, fmt.Errorf("no JWTs provided")
	}

	// Validate all JWTs have public keys
	for i, j := range jwts {
		if j.PublicKey == nil {
			return nil, fmt.Errorf("JWT %d missing public key", i)
		}
	}

	var circuitInstance frontend.Circuit
	var publicInputs *PublicInputs

	// Create circuit instance based on batch size
	// This is the circuit definition, not the assignment
	if len(jwts) == 1 {
		circuitInstance = &circuit.SingleECDSACircuit{}
	} else {
		circuitInstance = circuit.NewBatchECDSACircuit(len(jwts))
	}

	// Compile the circuit to get constraint system
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuitInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Now create the assignment (witness values)
	var assignment frontend.Circuit
	if len(jwts) == 1 {
		assignment, publicInputs = createSingleWitness(jwts[0])
	} else {
		a, pi, err := createBatchWitness(jwts)
		if err != nil {
			return nil, err
		}
		assignment = a
		publicInputs = pi
	}

	// Create witness from the assignment
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate the PLONK proof
	plonkProof, err := plonk.Prove(ccs, provingKey, fullWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	return &Proof{
		PlonkProof:       plonkProof,
		PublicInputs:     publicInputs,
		ConstraintSystem: ccs,
	}, nil
}

// createSingleWitness creates a witness for a single JWT
func createSingleWitness(j *jwt.ParsedJWT) (frontend.Circuit, *PublicInputs) {
	// Convert message hash to emulated field element
	messageHashInt := new(big.Int).SetBytes(j.MessageHash[:])

	witness := &circuit.SingleECDSACircuit{
		PublicKey: circuit.ECDSAPublicKey{
			X: emulated.ValueOf[circuit.P256Fp](j.PublicKey.X),
			Y: emulated.ValueOf[circuit.P256Fp](j.PublicKey.Y),
		},
		MessageHash: emulated.ValueOf[circuit.P256Fr](messageHashInt),
		Signature: circuit.ECDSASignature{
			R: emulated.ValueOf[circuit.P256Fr](j.SignatureR),
			S: emulated.ValueOf[circuit.P256Fr](j.SignatureS),
		},
	}

	publicInputs := &PublicInputs{
		PublicKeys: []*jwt.PublicKeyData{
			{
				X: j.PublicKey.X,
				Y: j.PublicKey.Y,
			},
		},
		MessageHashes: [][32]byte{j.MessageHash},
	}

	return witness, publicInputs
}

// createBatchWitness creates a witness for multiple JWTs
func createBatchWitness(jwts []*jwt.ParsedJWT) (frontend.Circuit, *PublicInputs, error) {
	batchSize := len(jwts)

	witness := circuit.NewBatchECDSACircuit(batchSize)
	publicKeys := make([]*jwt.PublicKeyData, batchSize)
	messageHashes := make([][32]byte, batchSize)

	for i, j := range jwts {
		// Public key
		witness.PublicKeys[i] = circuit.ECDSAPublicKey{
			X: emulated.ValueOf[circuit.P256Fp](j.PublicKey.X),
			Y: emulated.ValueOf[circuit.P256Fp](j.PublicKey.Y),
		}

		// Message hash
		messageHashInt := new(big.Int).SetBytes(j.MessageHash[:])
		witness.MessageHashes[i] = emulated.ValueOf[circuit.P256Fr](messageHashInt)

		// Signature (private)
		witness.Signatures[i] = circuit.ECDSASignature{
			R: emulated.ValueOf[circuit.P256Fr](j.SignatureR),
			S: emulated.ValueOf[circuit.P256Fr](j.SignatureS),
		}

		// Store public inputs
		publicKeys[i] = &jwt.PublicKeyData{
			X: j.PublicKey.X,
			Y: j.PublicKey.Y,
		}
		messageHashes[i] = j.MessageHash
	}

	publicInputs := &PublicInputs{
		PublicKeys:    publicKeys,
		MessageHashes: messageHashes,
	}

	return witness, publicInputs, nil
}
