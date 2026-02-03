# Gnark Transpilation Debugging Notes

## Project Overview

**Goal**: Transpile the Jolt zkVM verifier from Rust to Gnark circuits for Groth16 proof wrapping, enabling efficient on-chain verification.

**Branch**: `gnark-transpilation-parti` in `WonderJolt/jolt`

**Architecture**:
```
Rust Verifier (JoltField) --> Symbolic Execution (MleAst) --> AST --> Go/Gnark Circuit --> Groth16
```

The transpilation runs the Rust verifier with symbolic `MleAst` types instead of real field elements. Operations build an AST that gets converted to Gnark constraints. The `PartialEq` trait in constraint mode registers `(lhs - rhs) = 0` assertions.

---

## CRITICAL: Transcript Type Selection

**Jolt supports multiple transcript types via Cargo features:**

| Feature | Transcript | Default |
|---------|------------|---------|
| `transcript-poseidon` | PoseidonTranscriptFr | **Required for Gnark** |
| `transcript-keccak` | KeccakTranscript | No |
| `transcript-blake2b` | Blake2bTranscript | No |
| (none) | Blake2bTranscript | **Yes (default)** |

**IMPORTANT**: The Go circuit uses Poseidon hash. Therefore:
1. **Proof generation** must use `--features transcript-poseidon`
2. **Witness extraction** must use `--features transcript-poseidon`
3. **Testing/verification** must use `--features transcript-poseidon`

### Example Commands

```bash
# Generate proof with Poseidon transcript
cargo run -p fibonacci --release --features transcript-poseidon -- 50

# Run transpilation (already uses Poseidon via PoseidonAstTranscript)
cargo run -p gnark-transpiler --bin transpile_stages

# Debug with both features
cargo run -p fibonacci --release --features debug-expected-output,transcript-poseidon -- 10
```

---

## Verification Stages

| Stage | Status | Constraints | Description |
|-------|--------|-------------|-------------|
| 1 | **Working** | 158,006 | Spartan outer sumcheck |
| 2 | **Working** | +374,180 | Product virtualization, RAM RAF, Output check (5 batched sumchecks) |
| 3 | Pending | - | RAM/Register permutation (4 batched sumchecks) |
| 4 | Pending | - | Instruction lookups (3 batched sumchecks) |
| 5 | Pending | - | Hamming weight, Booleanity (2 batched sumchecks) |
| 6 | Pending | - | Opening reduction (1 sumcheck) |
| 7-8 | Future | - | Manual Go implementation (pairing checks) |

**Current Total (Stages 1-2)**: 532,186 constraints

---

## Key Files Reference

### Rust - Core Verifier
- `jolt-core/src/subprotocols/sumcheck.rs` - Batched sumcheck verifier
- `jolt-core/src/zkvm/spartan/mod.rs` - Spartan verification stages
- `jolt-core/src/zkvm/spartan/outer.rs` - Outer sumcheck (Stage 1)
- `jolt-core/src/zkvm/ram/output_check.rs` - Output sumcheck (Stage 2)
- `jolt-core/src/subprotocols/univariate_skip.rs` - Univariate skip optimization
- `jolt-core/src/transcripts/poseidon.rs` - Poseidon transcript implementation
- `jolt-core/src/field/mod.rs` - JoltField trait, OptimizedMul trait

### Rust - Transpilation
- `zklean-extractor/src/mle_ast.rs` - **Core AST for symbolic field operations**
- `gnark-transpiler/src/bin/transpile_stages.rs` - Transpilation entry point
- `gnark-transpiler/src/poseidon_transcript.rs` - PoseidonAstTranscript

### Go - Generated Circuit
- `gnark-transpiler/go/stages16_circuit.go` - Generated circuit
- `gnark-transpiler/go/stages16_witness.json` - Witness values
- `gnark-transpiler/go/poseidon/poseidon.go` - Poseidon implementation

---

## RESOLVED: Spurious Constraints from `is_one()` (2026-01-29)

### Problem
When enabling Stage 2 verification, spurious constraints appeared with the pattern:
```
(eq_product * value) - 1 = 0
```
Where `value` was 10 (fib input), 55 (fib(10) output), or 1.

This means the circuit was computing `eq_product = 1/value` as inverse constraints, which is incorrect.

### Investigation
Added debug logging to `add_constraint()` in `mle_ast.rs` to capture backtraces when constraints with suspicious values (10, 55, 1) were registered.

### Root Cause
The call chain was:
```
ProgramIOPolynomial::evaluate()
  -> MultilinearPolynomial::evaluate()
    -> OptimizedMul::mul_1_optimized()
      -> One::is_one()
        -> *self == Self::one()  // Default implementation!
          -> MleAst::eq()
            -> add_constraint((self - 1) = 0)  // SPURIOUS!
```

The `One::is_one()` trait has a default implementation `*self == Self::one()`. In MleAst's constraint mode, `==` calls `PartialEq::eq`, which registers `(self - 1) = 0` as a constraint. This happened when optimized multiplication checked if polynomial coefficients (10, 55) were 1.

### Fix Applied
**File**: [zklean-extractor/src/mle_ast.rs:1144-1157](zklean-extractor/src/mle_ast.rs#L1144-L1157)

```rust
impl One for MleAst {
    fn one() -> Self {
        Self::new_scalar(SCALAR_ONE)
    }

    /// Check if this MleAst represents the constant 1.
    ///
    /// IMPORTANT: This implementation checks the node structure directly
    /// instead of using `*self == Self::one()`. The default `is_one()`
    /// would trigger `PartialEq::eq`, which in constraint mode registers
    /// a constraint `(self - 1) = 0`. This caused spurious constraints
    /// involving io values (10, 55) when optimized multiplication checked
    /// if coefficients were 1.
    fn is_one(&self) -> bool {
        matches!(
            get_node(self.root),
            Node::Atom(Atom::Scalar(value)) if value == SCALAR_ONE
        )
    }
}
```

### Result
- **Before**: 7 assertions
- **After**: 4 assertions
- Spurious constraints with values 10 and 55 eliminated

### Lesson Learned
Any trait method that uses `==` internally can trigger spurious constraints in MleAst's constraint mode. Check for similar issues with:
- `Zero::is_zero()` - Already properly implemented (checks node directly)
- `One::is_one()` - **Fixed**
- Any other trait with default implementations using equality

---

## RESOLVED: Stage 2 Working End-to-End (2026-01-29)

After fixing the `is_one()` bug, Stage 2 now passes all tests.

### Verification Results (Stages 1-2)
```
Constraints: 532,186
Proof size:  164 bytes
Prove time:  1.60s
Verify time: 1.39ms
✓ Stages 1-6 circuit verification passed!
```

The constraint count increased from 158,006 (Stage 1 only) to 532,186 (Stages 1-2), adding ~374,180 constraints for the 5 batched sumchecks in Stage 2.

---

## RESOLVED: Stage 1 Working End-to-End (2026-01-29)

### Root Cause
The proof was generated with Blake2b transcript (default), but the Go circuit uses Poseidon hash. Different transcripts produce completely different challenge values.

### Fix
Use `--features transcript-poseidon` when generating proofs for Gnark transpilation.

### Verification Results (Stage 1 only)
```
Constraints: 158,006
Proof size:  164 bytes
Prove time:  460ms
Verify time: 1.3ms
```

---

## Technical Details

### Constraint Mode in MleAst

MleAst operates in two modes:
1. **Normal mode**: `==` compares NodeIds (structural equality)
2. **Constraint mode**: `==` registers `(lhs - rhs) = 0` constraint and returns `true`

Enable/disable with:
```rust
enable_constraint_mode();   // Start accumulating constraints
disable_constraint_mode();  // Stop
take_constraints();         // Get accumulated constraints
```

### Challenge Derivation Methods

Two methods for deriving challenges from transcript:

1. **`challenge_scalar_128_bits()`** - Used for batching coefficients
   - Hashes transcript state
   - Takes 16 bytes, reverses them, interprets as u128
   - Go equivalent: `poseidon.Truncate128(api, hash_state)`

2. **`challenge_scalar_optimized()`** - Used for sumcheck challenges
   - Hashes transcript state
   - Takes 16 bytes, reverses them, shifts by 2^192 for Montgomery form
   - Go equivalent: `poseidon.Truncate128Reverse(api, hash_state)`

### Per-Constraint CSE

Each assertion generates isolated subexpression trees to avoid node aliasing issues. The `perConstraintCse` function in the Go generator creates fresh variable bindings for each constraint.

---

## Debugging Techniques

### Adding Debug Logging to MleAst

To trace constraint registration, temporarily add to `add_constraint()` in `mle_ast.rs`:

```rust
fn add_constraint(constraint: MleAst) {
    // Check for suspicious scalar values
    fn check_for_value(node_id: NodeId, target: u64) -> bool {
        match get_node(node_id) {
            Node::Atom(Atom::Scalar(s)) => s[0] == target && s[1] == 0 && s[2] == 0 && s[3] == 0,
            Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => {
                check_for_value(*a, target) || check_for_value(*b, target)
            }
            Node::Neg(a) | Node::Inv(a) => check_for_value(*a, target),
            _ => false,
        }
    }

    if check_for_value(constraint.root, 10) || check_for_value(constraint.root, 55) {
        eprintln!("=== SUSPICIOUS CONSTRAINT ===");
        eprintln!("Constraint AST: {:?}", constraint);
        eprintln!("Backtrace:\n{}", std::backtrace::Backtrace::capture());
    }

    SYMBOLIC_CONSTRAINTS.with(|cell| {
        cell.borrow_mut().push(constraint);
    });
}
```

### Comparing Rust vs Go Values

```bash
# Generate debug output from Rust
cargo run -p fibonacci --release --features debug-expected-output,transcript-poseidon -- 10 2>&1 | tee /tmp/fib_debug.txt

# Compare with Go circuit solver
cd gnark-transpiler/go && go test -v -run TestStages16CircuitSolver
```

---

## Running Tests

### Quick Reference (Copy-Paste Commands)

```bash
# Full pipeline: generate proof, transpile, and test (fib(50))
cd /Users/home/dev/parti/cryptography/zkVMs/WonderJolt/jolt && \
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50 && \
cargo run -p gnark-transpiler --bin transpile_stages && \
cd gnark-transpiler/go && go test -v -run TestStages16CircuitProveVerify
```

### Step-by-Step

```bash
# 1. Generate proof with Poseidon transcript (IMPORTANT!)
#    Use any n value (10, 50, 100, etc.)
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50

# 2. Regenerate circuit from proof
cargo run -p gnark-transpiler --bin transpile_stages

# 3. Test Go circuit solver (fast, ~0.4s)
cd gnark-transpiler/go && go test -v -run TestStages16CircuitSolver

# 4. Full Groth16 prove/verify test (~20s)
cd gnark-transpiler/go && go test -v -run TestStages16CircuitProveVerify
```

### Verified Working (2026-01-30)

Tested with `fib(50)`, Stages 1-5:
- **Input**: n = 50
- **Output**: fib(50) = 12586269025
- **Trace length**: 1024
- **Constraints**: 1,531,516
- **Groth16 proof**: 164 bytes
- **Prove time**: 3.87s
- **Verify time**: 1.3ms

### Poseidon Width Benchmark (fib(50))

We tested different Poseidon widths to find the optimal configuration. Width refers to the internal state size; `new_circom(n)` takes n inputs and internally prepends a domain_tag (0), giving width = n + 1.

**Stage 1 only:**
| Width | Inputs | Data/hash | Constraints | Prove Time | Notes |
|-------|--------|-----------|-------------|------------|-------|
| 4 | 3 | 1 | **158,006** | 445ms | ✓ Best - current config |
| 5 | 4 | 2 | 178,202 | 499ms | +12.8% constraints |

**Stages 1-5:**
| Width | Inputs | Data/hash | Constraints | Prove Time | Notes |
|-------|--------|-----------|-------------|------------|-------|
| 4 | 3 | 1 | **1,531,516** | 3.87s | ✓ Best |
| 5 | 4 | 2 | 1,726,810 | 4.16s | +12.8% constraints |

**Why width-4 is optimal:**
- Larger widths (5+) have bigger MDS matrices, increasing per-permutation cost
- The savings from fewer permutations don't offset the larger matrix operations
- Width-4 (`new_circom(3)`) is the sweet spot

**Why not width-3?**
- `new_circom(2)` would give inputs = `[state, n_rounds]` with no data slot
- We need at least one data element to absorb per hash
- 3 inputs is the minimum viable configuration

---

## Context for Future Sessions

### What We're Doing
Transpiling the Jolt zkVM verifier (Rust) to Gnark circuits (Go) for Groth16 compilation. This enables wrapping Jolt proofs in a Groth16 proof for efficient on-chain verification.

### Current State (2026-01-30)
- **Stages 1-5**: Working (1,531,516 constraints)
- **Poseidon**: Width-4 (3 inputs via `new_circom(3)`) - optimal configuration
- **Stage 6**: Commented out, ready to enable
- **Tested**: fib(50) full Groth16 prove/verify passes

### Poseidon Configuration

The Poseidon hash uses width-4 internally (`new_circom(3)`):
- **Inputs**: `[state, n_rounds, data]` - 3 elements
- **Internal state**: `[domain_tag=0, state, n_rounds, data]` - width 4
- **One data element per permutation** - no batching

This is hardcoded and optimal based on benchmarks.

### Key Insight: MleAst Constraint Mode
The transpilation works by running the Rust verifier with `MleAst` (symbolic field elements) instead of real `Fr` values. In constraint mode:
- Arithmetic operations build an AST
- `==` comparisons register `(lhs - rhs) = 0` constraints
- Any trait method using `==` internally can cause spurious constraints

### Files Most Likely to Need Changes
1. `zklean-extractor/src/mle_ast.rs` - Core symbolic operations
2. `gnark-transpiler/src/bin/transpile_stages.rs` - Which stages are enabled
3. `jolt-core/src/zkvm/transpilable_verifier.rs` - Verifier configuration
