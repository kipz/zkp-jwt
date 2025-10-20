package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Setup performs the PLONK setup ceremony for the circuit
// This generates proving and verification keys
// For PLONK, this is a universal trusted setup that can be reused
func Setup(circuit frontend.Circuit) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	// Compile the circuit to get constraint system
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Generate unsafe SRS for testing/development
	// WARNING: This is not secure for production use!
	// In production, use pre-computed SRS from a trusted ceremony
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate SRS: %w", err)
	}

	// Generate proving key
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup: %w", err)
	}

	return pk, vk, nil
}

// SetupBatchCircuit is a helper to setup a batch circuit with the specified size
func SetupBatchCircuit(batchSize int) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	circuit := NewBatchECDSACircuit(batchSize)
	return Setup(circuit)
}

// SetupSingleCircuit is a helper to setup a single signature circuit
func SetupSingleCircuit() (plonk.ProvingKey, plonk.VerifyingKey, error) {
	circuit := &SingleECDSACircuit{}
	return Setup(circuit)
}
