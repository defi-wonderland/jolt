# Weekly Update - February 4, 2026

## Overview

Progress on the Jolt zkVM verifier transpilation to Gnark/Groth16. This week:
1. **Stages 2-5 working** - Full sumcheck verification pipeline now transpiles and verifies
2. **Hyrax efficiency investigation** - Deep dive into GLV endomorphism explaining ~3.5M constraint benchmark
3. **Poseidon width optimization** - Benchmarked different widths, confirmed width-4 (3 inputs) is optimal

---

## 1. Stages 2-5 Now Working

### Final Results

| Metric | Value |
|--------|-------|
| Assertions | 13 |
| Constraints | 1,531,516 |
| Proof size | 164 bytes |
| Prove time | 3.87s |
| Verify time | 1.59ms |

### Stage Breakdown

| Stage | Description | Cumulative Assertions | Cumulative Constraints |
|-------|-------------|----------------------|------------------------|
| 1 | Spartan outer sumcheck | 2 | 158,006 |
| 2 | Product, RAM RAF, Output check (5 batched sumchecks) | 4 | 532,186 |
| 3 | Shift, Instruction input, Register reduction (3 batched sumchecks) | 5 | 763,394 |
| 4 | Register r/w, RAM val evaluation, RAM val final (4 batched sumchecks) | 10 | 1,048,560 |
| 5 | Register val eval, RAM Hamming, RAM ra reduction, Lookups (4 batched sumchecks) | 13 | 1,531,516 |

### Sanity Check Results

- **100% rejection rate** on corrupted witnesses
- 20/20 random fuzzing tests rejected
- 6/6 targeted corruption tests rejected
- 5,924 Poseidon hash calls for Fiat-Shamir transcript

### Bugs Fixed This Week

1. **`is_one()` spurious constraints** (Stage 2)
   - Default `One::is_one()` uses `==`, triggering constraint registration
   - Fixed by checking node structure directly

2. **Node aliasing / CSE bug** (Stage 2)
   - Global CSE merged structurally identical EqPolynomial evaluations
   - Fixed with per-constraint CSE namespacing

3. **AST traversal memoization** (Stage 4)
   - Unmemoized traversal caused exponential blowup
   - Fixed by adding cache to recursive functions

4. **Stack overflow in codegen** (Stage 5)
   - Deep AST recursion exceeded stack
   - Fixed with iterative post-order traversal

Full details: [StagesSummary.md](February/StagesSummary.md)

---

## 2. Hyrax Efficiency Investigation

### The Question

The Hyrax verifier benchmark showed ~3.5M constraints for N=2^20 coefficients. How is this possible when MSMs are typically expensive?

### The Answer: GLV Endomorphism

**gnark uses GLV (Gallant-Lambert-Vanstone), NOT Pippenger.**

| Approach | Algorithm | Use Case | Key Property |
|----------|-----------|----------|--------------|
| Pippenger | Bucket sorting | Native MSMs | Batches additions across scalars |
| GLV | Endomorphism decomposition | Circuit MSMs | Halves scalar bit-length |

### How GLV Works

For curves with j-invariant 0 (Grumpkin, BN254), there exists an endomorphism:
$$\phi: (x, y) \mapsto (\beta x, -y)$$

where $\beta^3 = 1$ is a cube root of unity.

**The trick**: Decompose scalar $s$ into two ~127-bit scalars $s_1, s_2$:
$$s \equiv s_1 + \lambda \cdot s_2 \pmod{r}$$

Then compute:
$$[s]P = [s_1]P + [s_2]\phi(P)$$

Processing both simultaneously with Shamir's trick gives **~127 loop iterations instead of ~254**.

### Measured Costs

| Operation | Constraints |
|-----------|-------------|
| Point addition | 4 |
| DoubleAndAdd | 7 |
| Single scalar mul (GLV) | **1,775** |
| Joint scalar mul (2 scalars) | ~2,900 |

### Why 2-Cycle Matters

| Component | Field | In BN254 Circuit | Cost |
|-----------|-------|------------------|------|
| Grumpkin point $(x, y)$ | $\mathbb{F}_r$ | **Native** | ~5 constraints/op |
| Grumpkin scalar | $\mathbb{F}_q$ | Emulated | ~200 constraints/op |

Without the BN254/Grumpkin 2-cycle, MSM verification would be ~40x more expensive.

Full details: [WhyHyraxEfficient.md](February/WhyHyraxEfficient.md)

---

## 3. Poseidon Width Optimization

### The Question

Can we reduce constraint count by batching multiple data elements per Poseidon hash?

### Benchmark Results (fib(50))

**Stage 1 only:**
| Width | Inputs | Data/hash | Constraints | Prove Time |
|-------|--------|-----------|-------------|------------|
| 4 | 3 | 1 | **158,006** | 445ms |
| 5 | 4 | 2 | 178,202 | 499ms |

**Stages 1-5:**
| Width | Inputs | Data/hash | Constraints | Prove Time |
|-------|--------|-----------|-------------|------------|
| 4 | 3 | 1 | **1,531,516** | 3.87s |
| 5 | 4 | 2 | 1,726,810 | 4.16s |

### Conclusion

**Width-4 (3 inputs) is optimal.** Larger widths have bigger MDS matrices that cost more per permutation than they save from fewer permutations.

Configuration:
- `new_circom(3)` = 3 inputs = width-4 internally (domain_tag prepended)
- Inputs: `[state, n_rounds, data]`
- One data element per hash (no batching)

Width-3 (`new_circom(2)`) isn't viable because it would give `[state, n_rounds]` with no data slot.

### Code Cleanup

Applied semantic fix to make `append_message`, `append_u64`, `append_scalar` explicitly use direct poseidon calls instead of `hash_and_update()`. This makes the code structure match jolt-core's immediate hashing semantics.

---

## 4. Current Status

### What's Working

| Component | Status |
|-----------|--------|
| Stages 1-5 | ✅ Full Groth16 prove/verify |
| Poseidon transcript | ✅ Width-4 optimal |
| Sanity checks | ✅ 100% corruption rejection |

### What's Pending

| Component | Status | Notes |
|-----------|--------|-------|
| Stage 6 | Commented out | PCS opening verification |
| Stages 7-8 | Future | Pairing checks (manual Go) |
| Hyrax integration | Research | ~3.5M constraints feasible |

### Pipeline Commands

```bash
# Full pipeline
cd /Users/home/dev/parti/cryptography/zkVMs/WonderJolt/jolt
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50
cargo run -p gnark-transpiler --bin transpile_stages
cd gnark-transpiler/go && go test -v -run TestStages16CircuitProveVerify

# Quick solver test (~1s)
go test -v -run TestStages16CircuitSolver

# Sanity checks
go test -v -run "TestCorruptedWitnessRejected|TestRandomFuzzing"
```

---

## 5. Next Steps

1. **Enable Stage 6** - PCS opening reduction sumcheck
2. **Hyrax verifier integration** - Connect benchmark circuit with transpiled stages
3. **Real Jolt data validation** - Test with actual RecursionProver outputs
4. **Optimization** - Explore `WithNbScalarBits(125)` for challenge bounds

---

## Files Created/Modified This Week

| File | Purpose |
|------|---------|
| `docs/February/StagesSummary.md` | Complete reference for Stages 1-5 |
| `docs/February/WhyHyraxEfficient.md` | GLV endomorphism deep dive |
| `docs/gnark-transpilation-debugging.md` | Updated with Poseidon benchmarks |
| `gnark-transpiler/src/poseidon.rs` | Semantic fix for immediate hashing |
| `gnark-transpiler/src/codegen.rs` | Iterative traversal, per-constraint CSE |
| `zklean-extractor/src/mle_ast.rs` | `is_one()` fix, zero optimizations |

---

*Document generated: 2026-02-04*
*Last verified: Stages 1-5 passing with 1,531,516 constraints*
