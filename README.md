# ZKP-JWT: Zero-Knowledge Proofs for JWT Possession

Prove possession of one or more ECC-signed OIDC JWTs without revealing the signatures using zero-knowledge proofs.

## Overview

This Go library and CLI tool allows you to:
- Generate zero-knowledge proofs that you possess valid ES256 (P-256 ECDSA) signed JWTs
- Batch multiple JWT proofs into a single efficient proof
- Verify proofs without seeing the actual JWT signatures


## Architecture

### Technical Approach

```
┌──────────────┐
│ JWT 1, 2, N  │  (ES256 signed OIDC tokens)
└──────┬───────┘
       │ Parse & Extract
       ▼
┌──────────────────────────────────────────┐
│ ZK Circuit (gnark/PLONK)                │
│ ┌────────────────────────────────────┐  │
│ │ Private: signatures (r,s), messages│  │
│ │ Public: public keys, hashes        │  │
│ │                                    │  │
│ │ Constraints:                       │  │
│ │  ∀i: ECDSA_Verify(sig_i, msg_i,   │  │
│ │                    pubkey_i) = ✓   │  │
│ └────────────────────────────────────┘  │
└──────┬───────────────────────────────────┘
       │ Generate Proof
       ▼
┌──────────────┐
│ ZK Proof     │  (~small, fast to verify)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Verifier     │  ✓ Valid without seeing signatures
└──────────────┘
```

**Proof System:** PLONK with KZG commitments
- Universal trusted setup (one ceremony for all circuits)
- Fast proving time
- Constant proof size regardless of batch count
- No circuit-specific setup needed when changing batch sizes

**Supported Algorithms:**
- ES256 (P-256 / secp256r1 ECDSA)
- SHA-256 message hashing

## Installation

```bash
go install github.com/zkp-jwt/cmd/zkp-jwt@latest
```

Or build from source:

```bash
git clone https://github.com/zkp-jwt
cd zkp-jwt
go build -o zkp-jwt ./cmd/zkp-jwt
```

## Usage

### 1. Setup (One-time)

Generate universal PLONK parameters:

```bash
zkp-jwt setup --max-batch 10 --output keys/
```

This creates reusable proving/verification keys for circuits handling up to 10 JWTs.

### 2. Prove

Generate a proof of JWT possession:

```bash
# Single JWT
zkp-jwt prove --jwt token.jwt --keys keys/ --output proof.bin

# Multiple JWTs (batched)
zkp-jwt prove --jwt token1.jwt --jwt token2.jwt --jwt token3.jwt \
              --keys keys/ --output proof.bin
```

### 3. Verify

Verify a proof:

```bash
zkp-jwt verify --proof proof.bin --keys keys/ --public-keys pubkeys.json
```

## Library Usage

```go
package main

import (
    "github.com/zkp-jwt/pkg/circuit"
    "github.com/zkp-jwt/pkg/prover"
    "github.com/zkp-jwt/pkg/verifier"
    "github.com/zkp-jwt/pkg/jwt"
)

func main() {
    // Parse JWTs
    tokens := []string{jwtString1, jwtString2}
    parsedJWTs := make([]*jwt.ParsedJWT, len(tokens))
    for i, t := range tokens {
        parsedJWTs[i], _ = jwt.Parse(t)
    }

    // Setup circuit
    batchCircuit := circuit.NewBatchCircuit(len(parsedJWTs))
    pk, vk, _ := circuit.Setup(batchCircuit)

    // Generate proof
    proof, publicInputs, _ := prover.Prove(parsedJWTs, pk, batchCircuit)

    // Verify proof
    valid := verifier.Verify(proof, publicInputs, vk)
    println("Proof valid:", valid)
}
```

## Security Considerations

### Zero-Knowledge Properties
- **Completeness**: Valid JWTs always produce verifiable proofs
- **Soundness**: Cannot forge proofs without valid signatures
- **Zero-knowledge**: Verifier learns only that signatures are valid, not the signatures themselves

### Trusted Setup
- PLONK uses a universal trusted setup ceremony
- We use parameters from [Ethereum KZG ceremony](https://github.com/ethereum/kzg-ceremony)
- Setup is updateable and only needs one honest participant

### Limitations
- Only supports ES256 (P-256 ECDSA) signatures
- Circuit size must be determined at setup time (max batch size)
- Does not hide JWT claims (only signatures are private)
- Proving time grows linearly with number of JWTs

## License

MIT License

## References

- [gnark: Go ZK-SNARK library](https://github.com/Consensys/gnark)
- [PLONK Paper](https://eprint.iacr.org/2019/953)
- [JWT Specification (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [ECDSA Signature (FIPS 186-4)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
