# Stage 4: Registers R/W, RAM Val Evaluation, RAM Val Final

## Overview

Stage 4 contains 4 batched sumchecks that handle register consistency and RAM value computation:

| Sumcheck | Component | What it verifies |
|----------|-----------|------------------|
| **Register r/w** | Registers (Twist) | Read-checking and write-checking for registers |
| **RAM ra booleanity** | RAM (Twist) | RAM address one-hot/zero encoding |
| **RAM val evaluation** | RAM (Twist) | `f(k,j) = init + Σ Inc · ra` - virtualized memory state |
| **RAM val final** | RAM (Twist) | Final state matches (proves output check claim) |

From the Jolt verifier theory (see `docs/04_Jolt_Verifier_Theory.md`):
- Stage 4 receives claims from Stage 3's output
- Stage 4's output feeds Stage 5's inputs
- Mix of VIRTUAL and COMMITTED claims start appearing

## RESOLVED: Stage 4 Working (2026-01-29)

Stage 4 passed after fixing a performance bug in the transpiler.

### Results
```
Assertions: 10 (up from 5 in Stages 1-3)
Constraints: 1,048,560 (up from 763,394)
New constraints: +285,166
Proof size: 164 bytes
Prove time: 2.55s
Verify time: 1.44ms
```

### Bug Fixed: Memoization for AST Traversal

**Problem**: The transpiler hung for 6+ minutes at "Checking for Mul-by-Zero Pattern" step.

**Root Cause**: The `count_mul_by_zero` function recursively traversed the AST without memoization. With Stage 4's larger AST containing shared nodes (common subexpressions), the same nodes were visited exponentially many times.

**Fix**: Added a `HashMap<usize, usize>` cache to memoize visited nodes.

### Files Modified

1. **`jolt-core/src/zkvm/transpilable_verifier.rs:218`**
   - Changed: Uncommented `self.verify_stage4()?;`
   - Why: Enable Stage 4 verification in the transpilable verifier

2. **`gnark-transpiler/src/bin/transpile_stages.rs:199-240`**
   - Changed: Added memoization to `count_mul_by_zero` and `count_mul_by_zero_edge` functions
   - Why: Prevent exponential traversal of shared AST nodes
   - Before:
     ```rust
     fn count_mul_by_zero(node_id: usize) -> usize { ... }
     fn count_mul_by_zero_edge(edge: &Edge) -> usize { ... }
     ```
   - After:
     ```rust
     fn count_mul_by_zero(node_id: usize, cache: &mut HashMap<usize, usize>) -> usize { ... }
     fn count_mul_by_zero_edge(edge: &Edge, cache: &mut HashMap<usize, usize>) -> usize { ... }
     ```
   - Also added `let mut mul_zero_cache: HashMap<usize, usize> = HashMap::new();` before the loop

## Stage Position in Verification DAG

```
Stage 1 (Spartan outer)
    │ produces Az(r), Bz(r), Cz(r)
    ▼
Stage 2 (Spartan product, RAM raf, Output check, etc.)
    │ produces virtual claims
    ▼
Stage 3 (Spartan shift, Instruction input, Register claim reduction)
    │ produces claims on f(k,j), Inc(j)
    ▼
Stage 4 (Register r/w, RAM val evaluation, RAM val final)  ← WE ARE HERE
    │ produces claims on ra(r,j), Inc(j)
    ▼
Stage 5 (Register val evaluation, RAM ra reduction, Instruction read-raf)
    │
    ▼
... continues to Stage 8 (Dory PCS opening)
```

## Technical Details

### Register r/w Checking

Verifies that register reads return the correct virtualized state:

```
rv_rs1(r') = Σ_{j,k} eq(r',j) · ra_rs1(k,j) · f(k,j)
rv_rs2(r') = Σ_{j,k} eq(r',j) · ra_rs2(k,j) · f(k,j)
Inc(j) = wv_rd(j) - f(rd(j), j)  (implicit in write-checking)
```

Where:
- `f(k,j)` = virtualized register state at register k before cycle j
- `ra_rs1/rs2` = read address one-hot (derived from bytecode, PUBLIC)
- `Inc(j)` = increment at cycle j (new value - old value)

### RAM Val Evaluation

Proves the formula for virtualized memory state:

```
Val_final(r) - Val_init(r) = Σ_j Inc(j) · ra(r, j)
```

This sumcheck connects:
- Output check (Stage 2) claim on `Val_final(r)`
- Read/write checking claim on `f(k,j)`

### RAM Val Final

Verifies the final memory state is consistent with all the reads that occurred. This proves the output check claim from Stage 2.

### RAM RA Booleanity

Unlike register addresses (hardcoded in bytecode), RAM addresses are computed at runtime. The prover commits to `RamRa` chunks, so we verify they encode valid addresses:

```
hw² - hw = 0  (Hamming weight is 0 or 1)
```

- Zero rows for no-ops
- Exactly one bit set for memory accesses

## Key Files

### Verifier Implementation
- `jolt-core/src/zkvm/registers/read_write_checking.rs` - Register r/w sumcheck
- `jolt-core/src/zkvm/ram/val_evaluation.rs` - RAM val evaluation sumcheck
- `jolt-core/src/zkvm/ram/val_final.rs` - RAM val final sumcheck
- `jolt-core/src/zkvm/ram/mod.rs:new_ra_booleanity_verifier` - RA booleanity
- `jolt-core/src/zkvm/transpilable_verifier.rs:336-390` - Stage 4 verification

### Transpilation
- `zklean-extractor/src/mle_ast.rs` - Core AST operations
- `gnark-transpiler/src/bin/transpile_stages.rs` - Transpilation entry

## Commands

```bash
# Full pipeline with Stage 4
cd /Users/home/dev/parti/cryptography/zkVMs/WonderJolt/jolt && \
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50 && \
cargo run -p gnark-transpiler --bin transpile_stages && \
cd gnark-transpiler/go && go test -v -run TestStages16CircuitProveVerify
```

## Claim Flow from Theory

```
Stage 2: Output check
    │ claim on Val_final(r)
    ▼
Stage 4: RAM val evaluation
    │ proves Val_final(r) - Val_init(r) = Σ Inc(j) · ra(r, j)
    │
    ├─► claim on ra(r, j) → Stage 5: RAM ra reduction
    │
    └─► claim on Inc(j) → Stage 6: Inc reduction
```

The key insight: `Val_final` and `f(k,j)` are the *same* virtualized state polynomial evaluated at different points.
