# Weekly Update - January 29, 2026

## Jolt zkVM Verifier Transpilation to Gnark/Groth16

### Current Focus
Transpiling the Jolt verifier from Rust to Gnark circuits for Groth16 proof generation.

### Progress This Week

#### Completed
1. **Stage 1 Verifier Working End-to-End**
   - Spartan outer sumcheck fully transpiled
   - Generated Go circuit: `stages16_circuit.go` (1186 lines, 123KB)
   - All Poseidon transcript challenges verified to match between Rust and Go

2. **Fixed Node Aliasing Bug**
   - Implemented per-constraint CSE (Common Subexpression Elimination)
   - Each assertion now generates its own isolated subexpression tree
   - This fixed subtle aliasing issues where shared nodes caused incorrect evaluations

3. **Transcript Consistency Verified**
   - Created `compare_challenges.rs` binary to verify Fiat-Shamir transcript
   - Confirmed all challenges (preamble, commitments, tau, r0, batching_coeff, sumcheck rounds) match

#### Current Investigation: a1 Assertion Failure

**Status**: Debugging arithmetic computation in transpiled circuit

**Key Finding**:
- **Rust verifier PASSES** with fib(50): `output: 12586269025`, `valid: true`
- **Go circuit FAILS** on a1 assertion with error: `1693832296428195189627439502462433357945475970891388204017375550942439031428 != 0`

**What This Means**:
- The proof data is valid (Rust verifier confirms)
- All transcript challenges match (verified by test)
- The bug is in the **arithmetic computation** of `expected_output_claim` in the transpiled circuit

**The a1 Assertion Checks**:
```
sumcheck_output_claim - expected_output_claim * batching_coeff == 0
```

Where `expected_output_claim = tau_high_bound_r0 * tau_bound_r_tail_reversed * inner_sum_prod`

**Investigation Path**:
1. Compare `expected_output_claim` computation between Rust verifier (`outer.rs:409-438`) and Go circuit
2. Check if `inner_sum_prod` (R1CS evaluation) is computed correctly in the circuit
3. Verify `tau_high_bound_r0` and `tau_bound_r_tail_reversed` polynomial evaluations

### Architecture Overview
```
Rust Verifier (JoltField) --> Symbolic Execution (MleAst) --> AST --> Go/Gnark Circuit --> Groth16
```

### Key Files
- **Rust verifier**: `jolt-core/src/zkvm/spartan/outer.rs`
- **AST IR**: `zklean-extractor/src/mle_ast.rs`
- **Generated circuit**: `gnark-transpiler/go/stages16_circuit.go`
- **Poseidon hash**: `gnark-transpiler/go/poseidon/poseidon.go`

### Technical Details

**Two Truncation Methods**:
- `Truncate128`: Plain truncation (used for batching coefficients via `challenge_scalar`)
- `Truncate128Reverse`: Montgomery 125-bit mask (used for sumcheck challenges via `challenge_scalar_optimized`)

**Witness Files**:
- `witness_data.json` (51KB): Original Stage 1 test data
- `stages16_witness.json` (167KB): Extended witness for Stages 1-6

### Next Steps
1. Add debugging to identify where `expected_output_claim` computation diverges
2. Compare R1CS inner sum product evaluation between Rust and Go
3. Once Stage 1 passes in Stages 1-6 circuit, enable Stage 2 verification

### Roadmap
| Stage | Status | Description |
|-------|--------|-------------|
| 1 | In Progress | Spartan outer sumcheck |
| 2 | Pending | Product virtualization, RAM RAF, Output check (5 batched sumchecks) |
| 3 | Pending | RAM/Register permutation (4 batched sumchecks) |
| 4 | Pending | Instruction lookups (3 batched sumchecks) |
| 5 | Pending | Hamming weight, Booleanity (2 batched sumchecks) |
| 6 | Pending | Opening reduction (1 sumcheck) |
| 7-8 | Future | Manual Go implementation (pairing checks) |
