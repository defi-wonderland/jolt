# Poseidon Parameter Generation: Implementation Notes

Notes on integrating `poseidon-paramgen` into Jolt for verifiable Poseidon parameter generation.

---

## The Problem

Jolt's Poseidon PR (#1173) introduces a `PoseidonTranscript` that's generic over any field. The design uses a `PoseidonParams` trait:

```rust
pub trait PoseidonParams: PrimeField {
    fn poseidon() -> Poseidon<Self>;
}
```

Different fields need different Poseidon parameters—the MDS matrix, round constants, and even round counts depend on the field modulus. We need to:

1. **Support multiple fields**: At minimum Fr (scalar field) and Fq (base field) for BN254
2. **Verify parameters are correct**: 275 magic numbers that must be exactly right
3. **Make it auditable**: Anyone should be able to regenerate and verify the constants

### Why both Fr and Fq?

- **Fr (scalar field)**: Standard Poseidon use case—hashing within the SNARK circuit
- **Fq (base field)**: Needed for SNARK recursion—when verifying a BN254 proof inside another BN254 proof, the inner verifier operates in Fq

Currently we've implemented Fq parameters. Fr would follow the same process.

---

## The Solution: poseidon-paramgen

We use Penumbra's `poseidon-paramgen` library (audited by NCC Group, Summer 2022) to generate parameters deterministically. Given inputs (security level, width, field modulus), it outputs everything: alpha, round counts, MDS matrix, round constants.

### The arkworks Version Conflict

**Problem:** `poseidon-paramgen` v0.4.0 uses arkworks 0.4.x. Jolt uses arkworks 0.5.0. Cargo won't mix them.

**Solution:** We forked and created an `arkworks-0.5` branch:
- Repository: https://github.com/defi-wonderland/poseidon377
- Branch: `arkworks-0.5`

**Changes made:**
- Bumped `ark-ff`, `ark-std`, `ark-bn254`, etc. from 0.4 → 0.5 in Cargo.toml files
- One `vec!` macro import fix for `no_std` compatibility

That's it. The arkworks 0.4 → 0.5 API was nearly identical. The cryptographic logic is completely untouched.

**Outreach:** We sent a message to the Penumbra team asking if they'd maintain an `arkworks-0.5` branch upstream. (Do we know anyone at Penumbra? Worth asking around.)

---

## How poseidon-paramgen Works

The library generates all parameters deterministically from 4 inputs:

```rust
generate::<F>(M, t, p, allow_inverse)
//           │  │  │  └── allow α = -1 for S-box?
//           │  │  └───── field modulus
//           │  └──────── state width
//           └─────────── security level (bits)
```

| Component | Method | Output for BN254 Fq |
|-----------|--------|---------------------|
| **Alpha** | Smallest odd exponent coprime to p-1, ordered by addition chain depth | 5 |
| **Round counts** | Iterates (R_F, R_P), checks against statistical/interpolation/Gröbner attacks, adds safety margins | R_F=8, R_P=56 |
| **MDS matrix** | Deterministic Cauchy: `M[i][j] = 1/(x_i + y_j)` | 4×4 = 16 elements |
| **Round constants** | Merlin transcript seeded with all params, squeezes field elements | 64×4 = 256 values |

---

## What We Integrated

### Files Added/Modified

```
jolt-core/src/transcripts/
├── mod.rs                    # registers poseidon_param_gen module
├── poseidon.rs               # PoseidonTranscript + PoseidonParams trait
├── poseidon_fq_params.rs     # hardcoded Fq parameters
└── poseidon_param_gen.rs     # NEW: generation + verification
```

### Dependencies (Cargo.toml)

```toml
# Workspace root
poseidon-paramgen = { git = "https://github.com/defi-wonderland/poseidon377", branch = "arkworks-0.5" }
poseidon-parameters = { git = "https://github.com/defi-wonderland/poseidon377", branch = "arkworks-0.5" }

# jolt-core feature flag
transcript-poseidon = ["dep:light-poseidon", "dep:poseidon-paramgen", "dep:poseidon-parameters"]
```

### The Generation Function

```rust
pub fn generate_fq_params() -> PoseidonParameters<Fq> {
    let width = 4;           // t = 4 → rate 3, capacity 1
    let security_bits = 128;
    generate::<Fq>(security_bits, width, Fq::MODULUS, true)
}
```

To add Fr support, create `generate_fr_params()` with `Fr::MODULUS`.

---

## Our Configuration Choices

### Why 128-bit security?

Matches BN254's security level. No point hardening the hash beyond the curve—would just increase round counts and slow proofs.

### Why width 4 (rate 3)?

We need to hash 3 elements per call:
1. Previous transcript state
2. Domain separator
3. New data

Width = rate + capacity. With capacity = 1 (minimum for 128-bit security), width 4 gives rate 3.

### Open Question: Benchmark width 5 (rate 4)

With rate 4, we could hash 4 elements per call:
1. Previous transcript state
2. Domain separator
3. New data #1
4. New data #2

Trade-offs:
- Fewer permutation calls when absorbing multiple values
- MDS matrix grows: 4×4 (16) → 5×5 (25) elements
- Round constants grow: 256 → 320 values
- Round counts may change

**TODO:** Benchmark constraint count and prover performance for width 4 vs 5.

---

## The Trust Chain

```
Poseidon paper (Grassi et al., 2019)
    ↓ defines the math
poseidon-paramgen v0.4.0 (Penumbra)
    ↓ implements it in Rust
NCC Group audit (Summer 2022)
    ↓ verified the implementation
defi-wonderland/poseidon377 fork
    ↓ arkworks 0.4 → 0.5, Cargo.toml changes only
Our verification test
    ↓ regenerates and compares
Hardcoded values in poseidon_fq_params.rs
    ↓ used at runtime
light-poseidon hasher in PoseidonTranscriptFq
```

---

## Running the Tests

```bash
# Run all parameter generation tests
cargo test -p jolt-core --features transcript-poseidon poseidon_param_gen

# Run just the verification test
cargo test -p jolt-core --features transcript-poseidon verify_hardcoded_fq_params
```

---

## Open Questions

1. **Penumbra contact?** Do we know anyone there? Would be good to get the fork upstreamed.

2. **Width benchmarking priority?** Should we benchmark width 4 vs 5 before merging, or follow-up?

3. **Fr parameters?** Same process—just change `Fq` to `Fr`. When do we need this?

4. **Poseidon2?** We chose original Poseidon over Poseidon2 because:
   - `light-poseidon` only supports original Poseidon
   - poseidon-paramgen's Poseidon2 support (`v2` module) is **not audited**
   - Original Poseidon is more battle-tested (Zcash, Filecoin, etc. since 2019)

   **Performance note**: Poseidon2's simpler matrices (diagonal + low-rank vs dense MDS) reduce multiplications by up to 90%, giving ~2x native speed. However, **R1CS constraint counts are essentially identical** (~240 per hash for both, per [this benchmark](https://arxiv.org/abs/2409.01976)). Plonk shows mixed results depending on width. The main win is native speed, not circuit size.

   Worth revisiting for native hashing performance if we find an audited library.

5. **Parameter regeneration workflow?** Currently manual. Could automate with build script, but probably overkill unless we're frequently changing parameters.

---

## Discussion Notes (for call)

### Pending items

- **Could not find the new PR** with the changes on the last stages—need to follow up

### Scope clarification needed

We have AST transpilation working, including the Poseidon implementation (will test with more inputs). Questions for the team:

1. **Other teams' requirements?** You mentioned many teams were interested in transpilation to their stack. Are there specific requirements we should meet, or is the current thing enough?

2. **What's a nice deliverable?** Options:
   - **AST only**: Seems to be working, but we can keep testing with more Poseidon inputs
   - **AST + custom hash fallback**: Add custom implementation for hash functions that won't get transpiled to gnark (and don't need low constraints)
   - **Full verifier transpilation**: Complete transpilation of the verifier to gnark

3. **Next steps?** What would be most valuable to prioritize?

---
ya esta en production el verifier que va

ellos podrian usar bklake o poseidon

add blake support for the transpilation

same transcript for the extended instead of previous. Do we care about Fq about this in composition? he thinks not. Es mas natural usar mismo transcrip en todo el proving pupeline, a menos que switcheemos a Fq..
Suponete que stage 8 usa el ultimo y usa fq poseidon, el 9 usa sum check en este fq. 
por ahi tenemos que hacer algo con esto, pasar de un field a otro mid transpilation. habra un problema de seguridad aca? su intuicion dice que es fine, pero le va a preguntar a un amigo que es el autor de poseidon attack paper (de last summer). colisiones deberian recudir seguridad de forma negligible. 
o usamos el transcript con Fr en todo lado o switcheamos, pero esto ulktimo parece mas dangerous.
pensar en esto. recursion snark suele ser lo mas peligroso en estas cosas.

Scope: 
3 deliverables
Tener el transpiler que ande bien (optimizado)
y compilacion a un backend (gnark)

generic sum check es algo dificil para pensar dsps de la simple pipeline.

each scalar mult en grumpkin usa Fr (native). Deberia ser posible escribir una optimized set of constraints para esto.


--

native field mult they do in jolt quieren meterle un precompile super simple. Esto tiene sentido. Si sum checks perform sobre Fr, podes escribir en spartan un constarint para chequear mult en Fr. Es nativo en lo que hace sum check., Es el simplest precompile. 10x faster.
Por ej en en grumpkin msm esto es clave.

they got rid of flags and these because they were virtualized.