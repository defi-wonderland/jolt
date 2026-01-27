# Poseidon Parameter Generation: From Theory to Practice

The [Poseidon theory doc](./PoseidonTheory.md) explains *what* Poseidon parameters are and *why* they matter—the sponge construction, HADES rounds, state width and rate/capacity split, MDS matrices, all of it. Read that first if you haven't.

This document explains *how* we generate those parameters and *why* we don't just pick numbers by hand.

---

## The Problem: 275 Magic Numbers

Look at `poseidon_fq_params.rs`. You'll find:

- 1 alpha value (the S-box exponent)
- 2 round counts (full and partial)
- 16 MDS matrix elements (4×4)
- 256 round constants (64 rounds × 4 width)

That's 275 values that need to be *exactly right* for the hash to be secure. Where do they come from?

(The state width `t` isn't in this list—that's an input *we* choose based on how many elements we want to hash at once. The library generates everything else *for* that width.)

You could, in theory, pick them by hand. The Poseidon paper gives formulas. You could compute round counts on paper, construct a Cauchy matrix, derive constants from some seed. Researchers do this all the time.

But here's the thing: **one wrong constant breaks everything**.

A typo in the MDS matrix? Your hash might not be MDS anymore—diffusion fails, differential attacks become possible. Wrong round count? Gröbner basis attacks might succeed. Weak round constants? Algebraic structure an attacker can exploit.

The attack surface isn't "someone hacks your server." It's "someone made a transcription error in 2023 and nobody noticed."

---

## The Solution: Deterministic Generation

`poseidon-paramgen` is a Rust library (from Penumbra, audited by NCC Group in Summer 2022) that generates Poseidon parameters from first principles. You give it four inputs:

```rust
generate::<F>(
    M,              // Security level in bits
    t,              // State width (see theory doc for rate/capacity split)
    p,              // Field modulus
    allow_inverse,  // Allow α = -1 for the S-box?
)
```

It gives you back everything: alpha, round counts, MDS matrix, round constants. Deterministically. The same inputs always produce the same outputs.

For our BN254 Fq configuration:

```rust
pub fn generate_fq_params() -> PoseidonParameters<Fq> {
    generate::<Fq>(
        128,           // 128-bit security
        4,             // width 4 = rate 3 + capacity 1 → 3 inputs per hash
        Fq::MODULUS,   // BN254 base field
        true           // allow inverse alpha (won't be used)
    )
}
```

**Why 128-bit security?** This is the standard target for most cryptographic applications today. It matches BN254's security level—there's no point hardening the hash beyond the curve itself. Going higher (e.g., 256-bit) would increase round counts and slow down proofs for no practical benefit.

**Why width 4?** Width = rate + capacity. With capacity = 1 (minimum for 128-bit security in a ~254-bit field), width 4 gives us rate 3—meaning we can hash 3 field elements per permutation call. The [theory doc](./PoseidonTheory.md#3-state-width-t-and-ratecapacity-split) explains this tradeoff in detail.

> **Open question:** We currently use width 4 (rate 3). Higher widths like 5, 6, or 8 would allow more inputs per hash but change the MDS matrix size and round constants. We plan to benchmark how constraint count and prover performance change with different widths to find the optimal configuration for Jolt's workload.

The library outputs: α = 5, R_F = 8, R_P = 56, plus the 16-element MDS matrix and 256 round constants.

These are the values we hardcode in `poseidon_fq_params.rs` and feed to `light-poseidon`—the library that actually *performs* the Poseidon hash at runtime. `poseidon-paramgen` generates the parameters; `light-poseidon` uses them to hash.

---

## How Each Parameter Gets Chosen

### Alpha: The S-Box Exponent

Recall from the theory doc that the S-box is $x \mapsto x^\alpha$. For this to be a permutation (invertible), we need $\gcd(\alpha, p-1) = 1$.

But not all valid alphas are equal. Computing $x^{17}$ costs more than $x^5$. The metric is "addition chain depth"—how many multiplications to compute the power.

```
x^5:  x² = x·x,  x⁴ = x²·x²,  x⁵ = x⁴·x     → 3 multiplications
x^17: x² = x·x,  x⁴ = x²·x²,  x⁸ = x⁴·x⁴,  x¹⁶ = x⁸·x⁸,  x¹⁷ = x¹⁶·x  → 5 multiplications
```

The library maintains a list of exponents grouped by their [shortest known addition chain](https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html) depth—the minimum number of multiplications needed to compute $x^\alpha$:

```rust
depth_2: [4, 3]                                    // 2 multiplications
depth_3: [8, 6, 5]                                 // 3 multiplications ← 5 is here
depth_4: [16, 12, 10, 9, 7]                        // 4 multiplications
depth_5: [32, 24, 20, 18, 17, 15, 14, 13, 11]      // 5 multiplications
...
```

These aren't arbitrary—they're mathematically proven or exhaustively searched to be optimal. The list includes even values for completeness (it's copied from a general-purpose addition chain database), but the library skips them since even exponents can't be permutations.

It walks through this list, picking the **first odd exponent** that's coprime to $p-1$. For BN254's Fq, that's 5. For other fields like BLS12-377 (used by decaf377), it's 17—because that field's $p-1$ happens to be divisible by 3, 5, 7, 9, 11, 13, and 15, so all those candidates fail the coprimality check.

Why odd? Even exponents aren't permutations—$x^2$ maps both $a$ and $-a$ to the same value.

### Round Counts: Security Against Known Attacks

This is the security-critical calculation. The library determines the minimum rounds needed to resist three classes of attacks:

**1. Statistical attacks** (differential/linear distinguishers)

These track how input differences propagate through the hash. The full rounds with their wide S-box layers defeat these. The formula from Section 5.5.1 of the Poseidon paper:

```rust
if M <= (log2(p) - C) * (t + 1) {
    R_F_min = 6
} else {
    R_F_min = 10
}
```

For most configurations with 128-bit security, this gives R_F = 6. The library then adds a +2 safety margin → **R_F = 8**.

**2. Interpolation attacks**

An attacker tries to represent the hash output as a low-degree polynomial and interpolate it. The degree grows as $\alpha^r$ with rounds, so enough rounds make interpolation infeasible:

$$R \geq \frac{\log_\alpha(\min(M, \log_2 p))}{1} + \log_\alpha(t)$$

**3. Gröbner basis attacks**

The hash is a system of polynomial equations. Gröbner basis algorithms try to solve it directly. The complexity depends on the "degree of regularity" of the system. The Poseidon paper provides bounds; a 2023 paper by Ashur, Buschman, and Mahzoun tightened them.

The library iterates through all $(R_F, R_P)$ combinations:

```rust
for r_P in 1..400 {
    for r_F in 4..100 {
        if !is_secure_against_statistical(r_F) { continue; }
        if !is_secure_against_interpolation(r_F + r_P) { continue; }
        if !is_secure_against_grobner(r_F + r_P) { continue; }

        // Add safety margins: +2 to R_F, +7.5% to R_P
        // Pick the configuration with fewest S-boxes (lowest cost)
    }
}
```

For BN254 Fq with width 4 and 128-bit security: **R_F = 8, R_P = 56**.

### MDS Matrix: Deterministic Cauchy Construction

The MDS (Maximum Distance Separable) matrix provides diffusion. The theory doc explains what MDS means—any subset of input changes affects all outputs.

The library constructs a **Cauchy matrix**:

$$M[i][j] = \frac{1}{x_i + y_j}$$

where $x_i = [0, 1, 2, 3]$ and $y_j = [4, 5, 6, 7]$ for width 4.

```
M = [ 1/(0+4)  1/(0+5)  1/(0+6)  1/(0+7) ]     [ 1/4   1/5   1/6   1/7  ]
    [ 1/(1+4)  1/(1+5)  1/(1+6)  1/(1+7) ]  =  [ 1/5   1/6   1/7   1/8  ]
    [ 1/(2+4)  1/(2+5)  1/(2+6)  1/(2+7) ]     [ 1/6   1/7   1/8   1/9  ]
    [ 1/(3+4)  1/(3+5)  1/(3+6)  1/(3+7) ]     [ 1/7   1/8   1/9   1/10 ]
```

Division here is field inversion—$1/4$ means the multiplicative inverse of 4 in $\mathbb{F}_p$.

Why Cauchy matrices? They're provably MDS when constructed this way, and the construction is deterministic. No random sampling, no "try until you find a good one."

The original Poseidon paper describes checking matrices against "infinitely long subspace trails" (algorithms 1-3 from Grassi, Rechberger, Schofnegger 2020). The library skips this check for large fields (>128 bits) because the deterministic Cauchy construction has been empirically verified safe.

### Round Constants: Nothing Up My Sleeve

Round constants break symmetry and prevent structural attacks. They need to be:

1. **Deterministic**: Same parameters → same constants
2. **Unpredictable**: No algebraic structure an attacker can exploit
3. **Verifiable**: Anyone can recompute them

The library uses a **Merlin transcript** (a cryptographic sponge based on Strobe):

```rust
let mut transcript = Transcript::new(b"round-constants");
transcript.domain_sep::<F>(input_params, rounds, alpha);  // Commit to all parameters

let constants: Vec<F> = (0..num_rounds * width)
    .map(|_| transcript.round_constant())  // Squeeze field elements
    .collect();
```

The transcript is seeded with a fixed label (`"round-constants"`) and all the public parameters. Then it squeezes out field elements one by one. This is essentially a CSPRNG keyed by the parameters.

**Why Merlin instead of SHA3?** Merlin is designed for exactly this use case: deriving multiple field elements from structured inputs in a way that's domain-separated and streaming. SHA3 would work, but you'd need to manually handle:
- Encoding parameters into bytes
- Domain separation (so different parameter sets don't collide)
- Extracting arbitrary-length output
- Reducing bytes to field elements without bias

Merlin handles all of this with a clean API. It's also what Penumbra uses throughout their stack, so it was a natural choice for their library.

The "nothing up my sleeve" property: the constants are derived from the parameters in a transparent way. There's no room for someone to pick "weak" constants that enable a backdoor.

---

## Why Not Just Do This By Hand?

You could, technically. The formulas are public. But consider what you'd need to do:

1. **Alpha selection**: Check $\gcd(\alpha, p-1) = 1$ for each candidate. For a 254-bit prime, that's computing GCDs with 254-bit numbers. Doable, but tedious.

2. **Round count calculation**: Implement the security bounds from the Poseidon paper, plus the 2023 Gröbner basis improvements. Get the formulas wrong, and your hash is insecure. Get them too conservative, and your proofs are slower than necessary.

3. **MDS matrix**: Compute 16 field inversions. Verify the matrix is actually MDS (check all subdeterminants are nonzero). One arithmetic error and diffusion fails.

4. **Round constants**: Generate 256 field elements from a CSPRNG in a way that's reproducible and auditable. Implement the transcript protocol correctly.

5. **Transcription**: Copy all 275 values into your codebase without typos. In hex. With 64 characters each.

And then: how do you know you did it right?

The value of `poseidon-paramgen` isn't that it does something impossible. It's that it does something error-prone in an audited, deterministic, verifiable way.

---

## Our Generation and Verification Setup

The module `poseidon_param_gen.rs` contains the generation function:

```rust
use ark_bn254::Fq;
use ark_ff::PrimeField;
use poseidon_paramgen::v1::generate;
use poseidon_parameters::v1::PoseidonParameters;

/// Generate Poseidon parameters for BN254 Fq (base field)
pub fn generate_fq_params() -> PoseidonParameters<Fq> {
    let width = 4;           // t = 4 → rate 3, capacity 1
    let security_bits = 128;
    generate::<Fq>(security_bits, width, Fq::MODULUS, true)
}
```

To change the configuration, modify `width` or `security_bits` and regenerate. The library will compute new values for alpha, round counts, MDS matrix, and round constants.

**What `generate()` returns:**

```rust
PoseidonParameters<Fq> {
    M: 128,                    // security level (input)
    t: 4,                      // width (input)
    alpha: Alpha::Exponent(5), // S-box exponent (computed)
    rounds: RoundNumbers {
        r_F: 8,                // full rounds (computed)
        r_P: 56,               // partial rounds (computed)
    },
    mds: MdsMatrix([...]),     // 4×4 matrix (computed)
    arc: ArcMatrix([...]),     // 64×4 round constants (computed)
    // ... plus optimized versions of mds and arc
}
```

### Verification Test

We verify the hardcoded values in `poseidon_fq_params.rs` match what the library generates:

```rust
#[test]
fn verify_hardcoded_fq_params_match_generated() {
    let generated = generate_fq_params();

    // Check outputs match hardcoded values
    assert_eq!(generated.rounds.full(), FQ_FULL_ROUNDS);      // 8
    assert_eq!(generated.rounds.partial(), FQ_PARTIAL_ROUNDS); // 56
    assert_eq!(generated.alpha, Alpha::Exponent(FQ_ALPHA as u32));  // 5

    // MDS matrix (16 elements)
    for (i, row) in generated.mds.iter_rows().enumerate() {
        for (j, elem) in row.iter().enumerate() {
            let expected = Fq::from_be_bytes_mod_order(&hex_to_bytes(FQ_MDS[i][j]));
            assert_eq!(*elem, expected, "MDS mismatch at [{i}][{j}]");
        }
    }

    // Round constants (256 values)
    let constants: Vec<Fq> = generated.arc.iter_rows().flatten().cloned().collect();
    for (i, c) in constants.iter().enumerate() {
        let expected = Fq::from_be_bytes_mod_order(&hex_to_bytes(FQ_ROUND_CONSTANTS[i]));
        assert_eq!(*c, expected, "Round constant mismatch at index {i}");
    }
}
```

### Changing Parameters

To use different inputs (e.g., width 5 or 256-bit security):

1. Update `width` or `security_bits` in `generate_fq_params()`
2. Run generation to get new outputs
3. Replace constants in `poseidon_fq_params.rs` with the new MDS matrix and round constants
4. Update `light-poseidon` configuration to match the new width

---

## The Trust Chain

Here's the audit trail:

```
Poseidon paper (Grassi et al., 2019)
    ↓ (defines the math)
poseidon-paramgen v0.4.0 (Penumbra)
    ↓ (implements it in Rust)
NCC Group audit (Summer 2022)
    ↓ (verified the implementation)
defi-wonderland/poseidon377 fork
    ↓ (arkworks 0.4 → 0.5, API changes only)
Our verification test
    ↓ (regenerates and compares)
Hardcoded values in poseidon_fq_params.rs
    ↓ (used at runtime)
light-poseidon hasher in PoseidonTranscriptFq
```

The cryptographic logic is untouched from the audited version. Our fork only updates arkworks API calls—method renames, trait bounds—nothing that affects the math.

---

## Running the Verification

```bash
# Run all parameter generation tests
cargo test -p jolt-core --features transcript-poseidon poseidon_param_gen

# Run just the verification test
cargo test -p jolt-core --features transcript-poseidon verify_hardcoded_fq_params
```

Expected output:

```
running 4 tests
test transcripts::poseidon_param_gen::tests::verify_hardcoded_fq_params_match_generated ... ok
test transcripts::poseidon_param_gen::tests::print_generated_params_summary ... ok
test transcripts::poseidon_param_gen::tests::test_generated_params_work_with_light_poseidon ... ok
test transcripts::poseidon_param_gen::tests::test_fq_transcript_determinism ... ok
```

---

## Why BN254 Fq (Base Field) Instead of Fr (Scalar Field)?

Most Poseidon implementations use the scalar field (Fr). We use the base field (Fq). Why?

It's for **SNARK recursion**. When you verify a SNARK inside another SNARK, the inner verifier operates over the outer curve's scalar field. For BN254-based proofs verified inside another BN254 proof, the verifier arithmetic happens in Fq, not Fr.

Jolt needs to hash over Fq for the recursive verification step. That's why we generated Fq parameters specifically, and why `light-poseidon` (which Jolt uses for the actual hashing) needed to be configured with Fq constants.

The parameter generation is identical—same security level, same width, same alpha. Just a different field modulus.

---

## Why Poseidon, Not Poseidon2?

Poseidon2 (Grassi et al., 2023) is a newer variant with simpler internal matrices that's ~2x faster for native computation. Why didn't we use it?

**1. Battle-tested vs. newer**

Original Poseidon has been deployed in production since 2019—Zcash, Filecoin, Dusk, and many others. It's had years of cryptanalytic scrutiny. Poseidon2 is newer with less real-world deployment.

**2. Library support**

`light-poseidon` (what we use for actual hashing) only supports original Poseidon. Switching to Poseidon2 would require a different hashing library—likely [HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2) or [p3-poseidon2](https://crates.io/crates/p3-poseidon2).

**3. Audit status**

The `poseidon-paramgen` library has Poseidon2 support (the `v2` module), but from the README:

> "The audit covered only the parameter generation described in the original Poseidon paper. The Poseidon2 parameter generation is not yet audited."

**4. Performance: native vs. constraints**

Poseidon2's simpler matrices (diagonal + low-rank instead of dense MDS) reduce multiplications by up to 90%. But this mainly helps **native speed**, not constraint count:

- **Native speed**: ~2x faster hashing (fewer CPU multiplications). This is the main win.
- **Constraint count**: Despite fewer multiplications, constraint counts are **similar in practice**:
  - **R1CS (Groth16)**: ~240 constraints per hash for both Poseidon and Poseidon2 ([benchmarking paper](https://arxiv.org/abs/2409.01976))
  - **Plonk**: Varies by width. [TACEO benchmarks](https://core.taceo.io/articles/poseidon2-for-noir/) show t=4 is +0.3% worse, t=16 is −17% better for Poseidon2

  For R1CS (which Jolt uses), constraint counts are essentially identical.

Why the discrepancy? The constraint count depends on how the circuit is structured. Poseidon2's simpler matrix means fewer *field multiplications*, but the actual constraint count also depends on how additions, the S-box, and round structure are encoded. In practice, the savings don't always materialize.

| Aspect | Poseidon | Poseidon2 |
|--------|----------|-----------|
| Native speed | Baseline | ~2x faster |
| Constraint count | Baseline | Similar (varies by width/proof system) |
| Audit status | Extensive | Less audited |
| Production use | Years | Newer |
| light-poseidon support | ✓ | ✗ |

**Bottom line**: Poseidon2's main advantage is ~2x native speed, not constraint count. For Jolt's transcript hashing (computed natively), this would help. However, we chose original Poseidon because of better audit coverage and library support. If native hashing becomes a bottleneck, Poseidon2 is worth revisiting.

---

## References

- [Poseidon: A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2019/458) — Grassi et al., 2019
- [Algebraic Attacks on Poseidon](https://eprint.iacr.org/2023/537) — Ashur, Buschman, Mahzoun, 2023
- [poseidon377 repository](https://github.com/penumbra-zone/poseidon377) — Penumbra's implementation
- [NCC Group audit](https://research.nccgroup.com/2022/09/12/public-report-penumbra-labs-poseidon-audit/) — Summer 2022
- [Our arkworks 0.5 fork](https://github.com/defi-wonderland/poseidon377/tree/arkworks-0.5)
