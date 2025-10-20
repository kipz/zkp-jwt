package prover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
)

// SerializeProof writes a proof to a file
func SerializeProof(proof *Proof, filename string) error {
	// Serialize PLONK proof using WriteTo
	var proofBuf bytes.Buffer
	_, err := proof.PlonkProof.WriteTo(&proofBuf)
	if err != nil {
		return fmt.Errorf("failed to write proof: %w", err)
	}

	// Serialize public inputs
	publicInputsBytes, err := json.Marshal(proof.PublicInputs)
	if err != nil {
		return fmt.Errorf("failed to marshal public inputs: %w", err)
	}

	// Create combined structure
	serialized := struct {
		Proof        []byte `json:"proof"`
		PublicInputs []byte `json:"public_inputs"`
	}{
		Proof:        proofBuf.Bytes(),
		PublicInputs: publicInputsBytes,
	}

	// Write to file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(serialized); err != nil {
		return fmt.Errorf("failed to encode proof: %w", err)
	}

	return nil
}

// DeserializeProof reads a proof from a file
func DeserializeProof(filename string) (*Proof, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var serialized struct {
		Proof        []byte `json:"proof"`
		PublicInputs []byte `json:"public_inputs"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&serialized); err != nil {
		return nil, fmt.Errorf("failed to decode proof file: %w", err)
	}

	// Deserialize PLONK proof using ReadFrom
	plonkProof := plonk.NewProof(ecc.BN254)
	proofReader := bytes.NewReader(serialized.Proof)
	_, err = plonkProof.ReadFrom(proofReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}

	// Deserialize public inputs
	var publicInputs PublicInputs
	if err := json.Unmarshal(serialized.PublicInputs, &publicInputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public inputs: %w", err)
	}

	return &Proof{
		PlonkProof:   plonkProof,
		PublicInputs: &publicInputs,
	}, nil
}

// SerializeKeys writes proving and verification keys to files
func SerializeKeys(pk plonk.ProvingKey, vk plonk.VerifyingKey, pkFile, vkFile string) error {
	// Serialize proving key
	pkFileHandle, err := os.Create(pkFile)
	if err != nil {
		return fmt.Errorf("failed to create proving key file: %w", err)
	}
	defer pkFileHandle.Close()

	_, err = pk.WriteTo(pkFileHandle)
	if err != nil {
		return fmt.Errorf("failed to write proving key: %w", err)
	}

	// Serialize verification key
	vkFileHandle, err := os.Create(vkFile)
	if err != nil {
		return fmt.Errorf("failed to create verification key file: %w", err)
	}
	defer vkFileHandle.Close()

	_, err = vk.WriteTo(vkFileHandle)
	if err != nil {
		return fmt.Errorf("failed to write verification key: %w", err)
	}

	return nil
}

// DeserializeProvingKey reads a proving key from a file
func DeserializeProvingKey(filename string) (plonk.ProvingKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer file.Close()

	pk := plonk.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read proving key: %w", err)
	}

	return pk, nil
}

// DeserializeVerifyingKey reads a verification key from a file
func DeserializeVerifyingKey(filename string) (plonk.VerifyingKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open verification key file: %w", err)
	}
	defer file.Close()

	vk := plonk.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read verification key: %w", err)
	}

	return vk, nil
}
