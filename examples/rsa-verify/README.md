# rsa-verify

Proves RSA-2048 signature verification inside the Jolt zkVM, producing a 164-byte Groth16 proof
verifiable on-chain via a Solidity contract.

## How RSA-2048 Verification Works

Given a public key modulus `n` (2048-bit), signature `s`, and exponent `e = 65537`, verification
computes `s^e mod n` and checks it equals the expected value.

The dominant cost is modular exponentiation. Since 65537 in binary is `1 0000 0000 0000 0001`
(two 1-bits), only 17 squarings and 2 multiplications are needed via square-and-multiply.

The guest uses **Montgomery multiplication** to avoid large-integer division. All arithmetic is done
in Montgomery form where reduction mod n costs only shifts and additions, making it efficient in the
RISC-V execution trace.

```rust
#[jolt::provable(heap_size = 65536, max_trace_length = 4194304)]
fn rsa_verify(n: [u64; 32], sig: [u64; 32], expected: [u64; 32]) -> bool {
    let result = mod_exp_65537(&sig, &n);
    result == expected
}
```

Numbers are 2048-bit integers represented as little-endian `[u64; 32]` arrays (32 limbs × 64 bits).

## Size Class

`max_trace_length = 4194304 = 2^22` → size class **L** (`log_T = 22`).

This means all rsa-verify executions share the same gnark circuit and Groth16 trusted setup,
regardless of which keys are used. See [Size Classes](../../transpiler/README.md) for details.

## Test Vectors

The host has two hardcoded test vectors, selected with `--vector`:

| Flag | Modulus | Signature | Expected |
|------|---------|-----------|----------|
| `--vector 1` (default) | `N1` | `sig=2` | `2^65537 mod N1` |
| `--vector 2` | `N2` | `sig=3` | `3^65537 mod N2` |

Both `N1` and `N2` are real 2048-bit RSA moduli generated with `openssl genrsa 2048`.
See [`ottie-context/rsa-test-vectors.md`](../../../../ottie-context/rsa-test-vectors.md) for
instructions on generating additional test vectors.

## Basic Pipeline

### 1. Prove and save artifacts

```bash
cargo run -p rsa-verify --release --features transcript-poseidon,padded-io -- --save --vector 1
```

Writes to `/tmp/`:
- `rsa_verify_proof_1.bin` — serialized JoltProof (~91 KB)
- `rsa_verify_io_device_1.bin` — program I/O (~0.8 KB)
- `jolt_verifier_preprocessing.dat` — verifier preprocessing (~1.5 MB)

Runtime: ~20s.

### 2. Transpile to gnark circuit

```bash
cargo run -p transpiler --bin transpiler --release --features transcript-poseidon,padded-io \
  -- --proof /tmp/rsa_verify_proof_1.bin --io-device /tmp/rsa_verify_io_device_1.bin
```

Outputs to `transpiler/go/class_L/`:
- `stages_circuit.go` — gnark R1CS circuit (~5.7 MB, ~810K constraints)
- `stages_witness.json` — witness values (19,418 variables)

### 3. Sync circuit to root

```bash
cp transpiler/go/class_L/stages_circuit.go transpiler/go/stages_circuit.go
cp transpiler/go/class_L/stages_witness.json transpiler/go/stages_witness.json
```

### 4. Solver check (optional, ~1s)

```bash
cd transpiler/go/
go test -v -run TestStagesCircuitSolver -timeout 30m
```

Verifies all constraints are satisfied without any cryptography.

### 5. Groth16 prove + verify (~75s first run, faster after)

```bash
go test -v -run TestStagesCircuitProveVerify -timeout 60m
```

Runs trusted setup (cached to `class_L/` after first run), proves, and verifies.

### 6. Export Solidity verifier

```bash
JOLT_EXAMPLE=rsa-verify go test -v -run TestExportSolidity -timeout 60m
```

Writes:
- `transpiler/go/class_L/JoltVerifier_L.sol` — Solidity verifier with class L vk baked in
- `examples/rsa-verify/foundry/test/JoltVerifier.t.sol` — Foundry test with hardcoded proof

### 7. On-chain verification

```bash
cd examples/rsa-verify/foundry/
forge install foundry-rs/forge-std --no-git  # first time only
forge test -vv
```

Expected: `[PASS] test_rsa_verify() (gas: ~131,751,553)`

> **Note on gas:** ~131.7M gas exceeds the 30M mainnet block gas limit. rsa-verify is viable on L2s
> but not directly on L1. The high cost comes from 19,418 public inputs requiring 19,418 ecMul
> calls in the input accumulation step.

## Cross-Key Verification

This demonstrates that `JoltVerifier_L.sol` is universal: the same deployed contract can verify
RSA signatures from completely different key pairs. The circuit encodes *how* RSA verification works,
not *which keys* were used.

### Prepare witnesses for both vectors

```bash
# Vector 1
cargo run -p rsa-verify --release --features transcript-poseidon,padded-io -- --save --vector 1
cargo run -p transpiler --bin transpiler --release --features transcript-poseidon,padded-io \
  -- --proof /tmp/rsa_verify_proof_1.bin --io-device /tmp/rsa_verify_io_device_1.bin
cp transpiler/go/class_L/stages_witness.json transpiler/go/class_L/stages_witness_1.json

# Vector 2
cargo run -p rsa-verify --release --features transcript-poseidon,padded-io -- --save --vector 2
cargo run -p transpiler --bin transpiler --release --features transcript-poseidon,padded-io \
  -- --proof /tmp/rsa_verify_proof_2.bin --io-device /tmp/rsa_verify_io_device_2.bin
cp transpiler/go/class_L/stages_witness.json transpiler/go/class_L/stages_witness_2.json

cp transpiler/go/class_L/stages_circuit.go transpiler/go/stages_circuit.go
```

### Run the cross-key test

```bash
cd transpiler/go/
go test -v -run TestCrossKeyVerification -timeout 60m
```

Proves both witnesses using the **cached pk/vk** from `class_L/` (no re-setup). Generates
`examples/rsa-verify/foundry/test/JoltVerifierCrossKey.t.sol`.

### Verify on-chain

```bash
cd examples/rsa-verify/foundry/
forge install foundry-rs/forge-std --no-git  # first time only
forge test -vv --match-contract JoltVerifierCrossKeyTest
```

Expected:
```
[PASS] test_rsa_verify_vector1() (gas: ~131,751,562)   — n1, sig=2
[PASS] test_rsa_verify_vector2() (gas: ~131,751,528)   — n2, sig=3
```

Both proofs verified by the same `JoltVerifier_L.sol` contract.

## Key Numbers

| Metric | Value |
|--------|-------|
| RISC-V trace | ~2M cycles |
| Prover runtime | ~20s |
| Size class | L (log_T=22) |
| R1CS constraints | 810,872 |
| Public inputs | 19,418 |
| Trusted setup | ~64s (once per class) |
| Prove time | ~5.6s |
| Proof size | 164 bytes |
| Verify time | ~7.6ms |
| On-chain gas | ~131.7M (L2 recommended) |
