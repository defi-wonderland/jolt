# Stage 3: Spartan Shift, Instruction Input, Register Claim Reduction

## Overview

Stage 3 contains 3 batched sumchecks that are part of R1CS verification:

| Sumcheck | Component | What it verifies |
|----------|-----------|------------------|
| **Spartan shift** | R1CS | "Next-cycle" values (e.g., PC_{t+1}) match actual trace |
| **Spartan instruction input** | R1CS | Instruction operand constraints |
| **Register claim reduction** | Registers (Twist) | Batches register access claims |

From the Jolt verifier theory (see `docs/04_Jolt_Verifier_Theory.md`):
- These are sequential dependencies from Stage 2's output
- Stage 3's output feeds Stage 4's inputs
- All claims at this stage are still VIRTUAL (internal DAG edges)

## RESOLVED: Stage 3 Working (2026-01-29)

Stage 3 passed on first attempt with no issues!

### Results
```
Assertions: 5 (up from 4 in Stages 1-2)
Constraints: 763,394 (up from 532,186)
New constraints: +231,208
Proof size: 164 bytes
Prove time: 1.85s
Verify time: 1.44ms
```

### What This Means
The 3 batched sumchecks in Stage 3 added ~231k constraints to verify:
- Shift polynomial evaluation (next-cycle values)
- Instruction input constraints
- Register claim reduction

No debugging was needed - the `is_one()` fix from Stage 2 was sufficient.

## Key Files

### Verifier Implementation
- `jolt-core/src/zkvm/spartan/shift.rs` - Shift sumcheck
- `jolt-core/src/zkvm/spartan/instruction_input.rs` - Instruction input sumcheck
- `jolt-core/src/zkvm/spartan/claim_reductions.rs` - Register claim reduction
- `jolt-core/src/zkvm/transpilable_verifier.rs:307-334` - Stage 3 verification

### Transpilation
- `zklean-extractor/src/mle_ast.rs` - Core AST operations
- `gnark-transpiler/src/bin/transpile_stages.rs` - Transpilation entry

## Commands

```bash
# Full pipeline with Stage 3
cd /Users/home/dev/parti/cryptography/zkVMs/WonderJolt/jolt && \
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50 && \
cargo run -p gnark-transpiler --bin transpile_stages && \
cd gnark-transpiler/go && go test -v -run TestStages16CircuitProveVerify
```

## Stage Position in Verification DAG

```
Stage 1 (Spartan outer)
    │ produces Az(r), Bz(r), Cz(r)
    ▼
Stage 2 (Spartan product, RAM raf, Output check, etc.)
    │ produces virtual claims
    ▼
Stage 3 (Spartan shift, Instruction input, Register claim reduction)  ← WE ARE HERE
    │ produces claims on f(k,j), Inc(j)
    ▼
Stage 4 (Register r/w, RAM val evaluation, RAM val final)
    │
    ▼
... continues to Stage 8 (Dory PCS opening)
```

## Technical Details

### Spartan Shift
Verifies that "next-cycle" witness values like PC_{t+1} match the actual trace.
Key constraint: `(PC_{t+1} - PC_t - 4)(1 - JumpFlag_t) = 0`

### Instruction Input
Verifies instruction operand constraints - that the inputs to each instruction are wired correctly.

### Register Claim Reduction
Batches register access claims from read-checking and write-checking.
The register addresses (rs1, rs2, rd) are derived from bytecode, which is PUBLIC.

## Circuit Verification (Not Passing Blindly)

Verified the generated `stages16_circuit.go` (1320 lines) contains legitimate verification logic:

### 5 Assertions in `Define()` Function
| Assertion | What it verifies |
|-----------|------------------|
| `a0` | UniSkip coefficient verification |
| `a1` | Stage 1 sumcheck output |
| `a2` | Stage 2 UniSkip verification |
| `a3` | Stage 2 sumcheck output |
| `a4` | Stage 3 sumcheck output (NEW) |

### Cryptographic Operations Present
- **Poseidon hash chains**: `poseidon.Hash2(api, ...)` for Fiat-Shamir transcript
- **Challenge derivation**: `poseidon.Truncate128Reverse(api, hash)` for sumcheck challenges
- **EQ polynomial evaluations**: `api.Add(api.Mul(x, y), api.Mul(api.Sub(1, x), api.Sub(1, y)))`
- **Field arithmetic**: `api.Add`, `api.Sub`, `api.Mul`, `api.Inverse`

### Assertion Structure
Each assertion follows the pattern:
```go
a4 := api.Sub(sumcheck_output, api.Mul(expected, batching_coeff))
api.AssertIsEqual(a4, 0)
```

This confirms the circuit is performing actual cryptographic verification, not just returning success.
