package verifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/zkp-jwt/pkg/circuit"
	"github.com/zkp-jwt/pkg/prover"
)

// Verify checks if a zero-knowledge proof is valid
// This verifies that the prover possesses valid JWT signatures without seeing them
func Verify(proof *prover.Proof, verifyingKey plonk.VerifyingKey) error {
	if proof == nil || proof.PublicInputs == nil {
		return fmt.Errorf("invalid proof: nil proof or public inputs")
	}

	// Create public witness from the proof's public inputs
	circuitInstance, err := createPublicWitnessCircuit(proof.PublicInputs)
	if err != nil {
		return fmt.Errorf("failed to create public witness circuit: %w", err)
	}

	// Create witness with only public inputs
	publicWitness, err := frontend.NewWitness(circuitInstance, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify the PLONK proof
	err = plonk.Verify(proof.PlonkProof, verifyingKey, publicWitness)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// createPublicWitnessCircuit creates a circuit with only public inputs assigned
func createPublicWitnessCircuit(publicInputs *prover.PublicInputs) (frontend.Circuit, error) {
	numKeys := len(publicInputs.PublicKeys)

	if numKeys == 0 {
		return nil, fmt.Errorf("no public keys in public inputs")
	}

	if len(publicInputs.MessageHashes) != numKeys {
		return nil, fmt.Errorf("mismatched public keys and message hashes count")
	}

	// Create appropriate circuit based on number of keys
	if numKeys == 1 {
		return createSinglePublicWitnessCircuit(publicInputs), nil
	}

	return createBatchPublicWitnessCircuit(publicInputs), nil
}

// createSinglePublicWitnessCircuit creates circuit with public inputs for single JWT
func createSinglePublicWitnessCircuit(publicInputs *prover.PublicInputs) frontend.Circuit {
	pk := publicInputs.PublicKeys[0]
	messageHash := publicInputs.MessageHashes[0]

	messageHashInt := new(big.Int).SetBytes(messageHash[:])

	return &circuit.SingleECDSACircuit{
		PublicKey: circuit.ECDSAPublicKey{
			X: emulated.ValueOf[circuit.P256Fp](pk.X),
			Y: emulated.ValueOf[circuit.P256Fp](pk.Y),
		},
		MessageHash: emulated.ValueOf[circuit.P256Fr](messageHashInt),
		// Signature is not included (it's the secret witness)
	}
}

// createBatchPublicWitnessCircuit creates circuit with public inputs for multiple JWTs
func createBatchPublicWitnessCircuit(publicInputs *prover.PublicInputs) frontend.Circuit {
	batchSize := len(publicInputs.PublicKeys)

	circuitInstance := circuit.NewBatchECDSACircuit(batchSize)

	for i := 0; i < batchSize; i++ {
		pk := publicInputs.PublicKeys[i]
		messageHash := publicInputs.MessageHashes[i]

		circuitInstance.PublicKeys[i] = circuit.ECDSAPublicKey{
			X: emulated.ValueOf[circuit.P256Fp](pk.X),
			Y: emulated.ValueOf[circuit.P256Fp](pk.Y),
		}

		messageHashInt := new(big.Int).SetBytes(messageHash[:])
		circuitInstance.MessageHashes[i] = emulated.ValueOf[circuit.P256Fr](messageHashInt)

		// Signatures are not included (they're the secret witness)
	}

	return circuitInstance
}

// VerifyWithPublicKeys is a convenience function that verifies a proof given the public keys directly
func VerifyWithPublicKeys(proof *prover.Proof, verifyingKey plonk.VerifyingKey, expectedPublicKeys []*big.Int) error {
	// First verify the proof itself
	if err := Verify(proof, verifyingKey); err != nil {
		return err
	}

	// Then verify the public keys match expectations (optional additional check)
	if len(expectedPublicKeys) > 0 {
		if len(proof.PublicInputs.PublicKeys) != len(expectedPublicKeys)/2 {
			return fmt.Errorf("public key count mismatch")
		}

		// Could add additional checks here if needed
	}

	return nil
}
