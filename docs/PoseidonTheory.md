# Poseidon: Arithmetic-Friendly Hashing

Why would anyone need *another* hash function when SHA-256 and BLAKE3 work perfectly well? The answer lies in a fundamental mismatch between how traditional hash functions operate and what zero-knowledge proof systems require.

---

## The Problem: Hash Functions Inside Circuits

Imagine you want to prove something about a Merkle tree without revealing its contents. Perhaps you're proving you own a certain amount of cryptocurrency, or that you're a member of a group, or that a private transaction is valid. The standard approach: generate a zero-knowledge proof that you know a path from a leaf to the root, where each step involves hashing.

Here's where it gets painful. Zero-knowledge proof systems like SNARKs and STARKs don't execute code the way a CPU does. They convert computations into arithmetic circuits—essentially giant systems of polynomial equations over a finite field. To prove you computed something correctly, you prove that certain polynomial relationships hold.

The cost metric isn't "CPU cycles" but "constraints"—the number of polynomial equations needed to express your computation. And this is where SHA-256 and other traditional hash functions fall apart.

(A caveat: modern proof systems increasingly use *lookup arguments*, which let you prove that a value appears in a precomputed table rather than re-deriving it with constraints. This makes bit operations cheaper—you can look up XOR results instead of constraining them. Lookup-friendly hashes like Keccak become more viable in these systems. But lookups aren't free either, and for many applications—especially recursive proofs, small circuits, or systems without efficient lookups—arithmetic-native hashes still dominate.)

SHA-256 was designed for CPUs. It uses operations that CPUs handle efficiently: 32-bit XOR, 32-bit addition with carry propagation, bit rotations, and boolean operations like `(x AND y) XOR (NOT x AND z)`. On silicon, these are blazingly fast. But inside an arithmetic circuit over a prime field? They're catastrophically expensive.

Consider a single XOR operation. In normal computation, XOR is one instruction. But in a prime field $\mathbb{F}_p$, there's no native XOR. You have to express each bit as a separate field element, enforce that it's boolean (0 or 1) with a constraint like $b_i \cdot (1 - b_i) = 0$, then compute the XOR bit-by-bit as $a_i + b_i - 2 \cdot a_i \cdot b_i$. A 256-bit XOR that takes one CPU cycle now requires hundreds of constraints.

**The numbers are sobering.** Expressing SHA-256 in a SNARK circuit costs roughly 25,000–30,000 constraints per hash. If you're proving a Merkle path of depth 20 (a tree with a million leaves), that's 20 hashes, which is 500,000–600,000 constraints. For a tree of depth 30? Nearly a million constraints—just for the hash operations.

This isn't a theoretical concern. Real-world zk-rollups and privacy protocols like Zcash spend enormous computational resources proving hash computations. Proof generation time scales with constraint count. Memory usage scales with constraint count. The hash function becomes the bottleneck.

**The question crystallizes: Can we design a hash function that's native to arithmetic circuits?**

---

## The Insight: Go Native

Traditional hash functions speak the language of bits. They think in terms of XOR, shifts, and boolean logic. Zero-knowledge circuits speak the language of field arithmetic. They think in terms of addition and multiplication over $\mathbb{F}_p$.

The insight behind Poseidon: design a hash function that speaks the circuit's native language. Use only operations that are cheap in arithmetic circuits—field addition, field multiplication, and nothing else. No bit operations at all.

This isn't just an optimization. It's a paradigm shift. Instead of "implement SHA-256 in a circuit" (forcing a square peg into a round hole), we ask "what hash function would we design if we were circuit architects from the start?"

The answer is Poseidon: a hash function built from the ground up for prime fields, where every operation maps directly to a small number of circuit constraints.

---

## The Foundation: Sponge Construction

Before diving into Poseidon's specifics, we need to understand sponge constructions—the framework that underlies Poseidon (and also SHA-3, for that matter).

A sponge is a way to turn a fixed-width permutation into a variable-length hash function. Think of it as a state machine with two operations:

**Absorb**: Mix input data into the state.
**Squeeze**: Extract output data from the state.

The state has two parts:
- The **rate** portion ($r$ elements): This is where inputs enter and outputs exit.
- The **capacity** portion ($c$ elements): This is "internal plumbing"—never directly exposed, providing security margin.

```
┌─────────────────────────────────────┐
│         State (t elements)           │
│  ┌─────────────────┬───────────────┐ │
│  │   Rate (r)      │  Capacity (c) │ │
│  │   Input/Output  │   Security    │ │
│  └─────────────────┴───────────────┘ │
└─────────────────────────────────────┘
```

The protocol:

1. **Initialize**: Set state to zero (or to a domain separator).
2. **Absorb**: For each input block of $r$ elements:
   - Add input elements to the rate portion.
   - Apply the permutation $\pi$ to the entire state.
3. **Squeeze**: Read output elements from the rate portion:
   - Output the rate portion.
   - If you need more output, apply $\pi$ again and repeat.

Why does this work? The permutation thoroughly mixes the entire state—both rate and capacity. After absorbing all inputs and applying $\pi$ one final time, the capacity portion is entangled with all inputs but never revealed. An attacker who doesn't know the full internal state can't predict outputs or find collisions easily.

The security level is roughly $c/2$ bits (birthday bound on the capacity). For 128-bit security, you need $c \geq 256$ bits, or around 4 field elements for a ~64-bit prime.

**Why sponges for ZK?** Sponges are naturally suited to arithmetic circuits because:
- Variable-length input handling is clean (just keep absorbing).
- The permutation is the only component you need to optimize.
- No finalization step with different structure—it's all just permutation calls.

If we can build an efficient permutation over field elements, we get an efficient hash function.

So what does "efficient permutation" actually mean? What's inside the $\pi$ black box? That's where Poseidon's real contribution lies.

---

## Poseidon's Permutation: The HADES Strategy

Poseidon's core is a permutation $\pi : \mathbb{F}_p^t \to \mathbb{F}_p^t$. It takes $t$ field elements and shuffles them thoroughly. The design is called **HADES** (a hybrid of different round types), and it's built to minimize circuit constraints while maintaining cryptographic security.

Each round of Poseidon consists of three layers:

### Layer 1: Add Round Constants (ARC)

Add a unique constant to each state element:
$$x_i \leftarrow x_i + c_i^{(r)}$$

This breaks symmetry and prevents attacks that exploit structure. Each round has different constants, derived by hashing a seed—nothing up the designers' sleeves.

**Cost**: $t$ additions. In a circuit, additions are essentially free (they're linear constraints, which SNARK systems handle implicitly). **Cost: 0 constraints.**

### Layer 2: S-Box (Nonlinearity)

Apply a nonlinear function to each state element. Poseidon uses the power map:
$$x_i \leftarrow x_i^\alpha \quad \text{for each } i \in \{0, 1, \ldots, t-1\}$$

So if your state is $(x_0, x_1, x_2)$, it becomes $(x_0^5, x_1^5, x_2^5)$ after the S-box layer (assuming $\alpha = 5$).

The exponent $\alpha$ is typically 5 (for most prime fields) or 7, chosen so that $\gcd(\alpha, p-1) = 1$. This coprimality condition ensures the S-box is a permutation over $\mathbb{F}_p$—every output has exactly one input that maps to it, so the function is invertible.

Why $x^5$? It's the smallest odd exponent that's invertible (needed for the permutation property) and provides sufficient nonlinearity against algebraic attacks. $x^3$ is too weak; $x^5$ hits the sweet spot.

**Cost**: Each $x^5$ operation requires just 2 multiplications:
$$x^2 = x \cdot x$$
$$x^4 = x^2 \cdot x^2$$
$$x^5 = x^4 \cdot x$$

In SNARK terms, that's 2 constraints per S-box. For $t$ state elements with full S-boxes, that's $2t$ constraints per round.

### Layer 3: Mix Layer (MDS Matrix)

Multiply the state by an MDS (Maximum Distance Separable) matrix:
$$\vec{x} \leftarrow M \cdot \vec{x}$$

An MDS matrix ensures that any two input elements changing will affect all output elements. This provides diffusion—spreading local changes across the entire state.

**Cost**: Matrix multiplication is all additions and multiplications. For a $t \times t$ matrix, that's $t^2$ multiplications per round. However, these are linear operations on the state, which are cheap. **Cost: 0 additional constraints** (in R1CS systems, linear combinations are free).

Wait—$t^2$ multiplications cost zero? Almost. In R1CS (Rank-1 Constraint Systems, the format SNARKs use), a constraint has the form:
$$(\text{linear combo of variables}) \times (\text{linear combo}) = (\text{linear combo})$$

Since the MDS layer is just linear combinations of variables, it can be absorbed into the next nonlinear operation. The multiplications in the MDS matrix are multiplications by *constants*, not variables—and multiplying by a constant is free in R1CS.

**What about PLONK and other arithmetizations?** The "linear operations are free" property is specific to R1CS. In PLONK-style systems, every operation—addition or multiplication—consumes a row in the execution trace. The cost model shifts from "count the multiplications" to "count the total operations."

Does this mean Poseidon is only optimized for R1CS? Not quite. The core insight—use native field operations instead of bit manipulations—still applies. A field multiplication is one PLONK gate; a 32-bit XOR is still dozens of gates even in PLONK. Poseidon remains far cheaper than SHA-256 in any arithmetization.

That said, PLONK-optimized variants exist. Poseidon2 restructures the linear layer to reduce total operations (not just nonlinear ones), making it faster across all proof systems. And some PLONK systems use custom gates tailored to specific S-boxes, further reducing costs.

### The HADES Trick: Partial vs. Full Rounds

Here's where Poseidon gets clever. In a standard substitution-permutation network, you'd apply S-boxes to all state elements every round. That's $2t$ constraints per round. For security, you might need 60+ rounds—totaling over $120t$ constraints.

The HADES design uses two types of rounds:

**Full rounds**: Apply S-boxes to *all* $t$ state elements. Expensive (costs $2t$ constraints each), but necessary for security against statistical attacks like differential cryptanalysis.

**Partial rounds**: Apply an S-box to *only one* state element; the others pass through unchanged. Cheap (costs just 2 constraints each). The MDS matrix still spreads this single nonlinear transformation across all elements.

```
Full round:          Partial round:
┌───┬───┬───┬───┐    ┌───┬───┬───┬───┐
│S  │S  │S  │S  │    │S  │   │   │   │  ← Only one S-box
├───┼───┼───┼───┤    ├───┼───┼───┼───┤
│   MDS Matrix  │    │   MDS Matrix  │
└───────────────┘    └───────────────┘
```

The total number of each type is a security parameter: $R_F$ full rounds and $R_P$ partial rounds. A typical configuration might be $R_F = 8$ and $R_P = 56$.

The structure arranges them in a sandwich:
- First $R_F/2$ full rounds (e.g., 4 full rounds)
- Then all $R_P$ partial rounds in the middle (e.g., 56 partial rounds)
- Finally another $R_F/2$ full rounds (e.g., 4 full rounds)

**Why does this work?** The full rounds at the beginning and end provide resistance against differential and linear cryptanalysis—attacks that track how differences propagate through the function. The partial rounds in the middle provide resistance against algebraic attacks (like Gröbner basis attacks that try to solve the polynomial system directly). The MDS matrix in partial rounds ensures that even one S-box's nonlinearity eventually reaches all state elements.

**The constraint savings are dramatic.** Consider a Poseidon instance with $t = 3$:

- Full round cost: $2 \times 3 = 6$ constraints
- Partial round cost: $2 \times 1 = 2$ constraints

With $R_F = 8$ and $R_P = 56$:
- Full rounds: $8 \times 6 = 48$ constraints
- Partial rounds: $56 \times 2 = 112$ constraints
- **Total: 160 constraints per hash**

Compare to SHA-256's ~25,000 constraints. That's a **150× improvement**.

---

## Parameter Selection: Security Analysis

Poseidon's security depends on choosing $R_F$ and $R_P$ correctly. Too few rounds, and attackers can break it. Too many, and you're wasting constraints.

### Threat Model: Algebraic Attacks

The main worry for any arithmetic-native hash is algebraic attacks. Since everything is polynomial arithmetic over a field, an attacker might try to:

1. **Gröbner basis attacks**: Represent the hash as a system of polynomial equations and solve it directly. The S-box $x^5$ creates degree-5 equations; after $r$ rounds, the algebraic degree is $5^r$. For large enough $r$, this becomes infeasible.

2. **Interpolation attacks**: If the output polynomial has low degree, an attacker might interpolate it and invert. The degree grows exponentially with rounds.

3. **GCD attacks**: For sponge constructions specifically, find relationships between inputs and outputs.

### The Security Margin

Poseidon's designers (Grassi et al., 2019) provide explicit formulas for minimum round counts based on the field size and state width. The key parameters:

- **Full rounds ($R_F$)**: Determined by statistical attacks. With an MDS matrix and $\alpha = 5$, $R_F = 8$ provides a comfortable margin against differential and linear cryptanalysis.

- **Partial rounds ($R_P$)**: Determined by algebraic attacks. The formula accounts for Gröbner basis complexity:
  $$R_P \geq \frac{\log_2(p) \cdot \min(M, \lceil \log_2(p) \rceil)}{\log_2(\alpha)}$$

  where $M$ is the security level in bits. For 128-bit security and a 256-bit prime, this typically gives $R_P \approx 56-60$.

### Concrete Parameters

For different use cases, here are typical Poseidon configurations:

| Use Case | State Size ($t$) | $R_F$ | $R_P$ | Constraints |
|----------|------------------|-------|-------|-------------|
| 2-to-1 compression (Merkle trees) | 3 | 8 | 56 | ~160 |
| 4-to-1 compression | 5 | 8 | 60 | ~230 |
| General hashing | 9 | 8 | 57 | ~350 |
| High security (256-bit) | 3 | 8 | 120 | ~280 |

These numbers assume a ~255-bit prime field (like BN254 or BLS12-381's scalar field) and $\alpha = 5$.

---

## Choosing Parameters in Practice

When you use a Poseidon implementation, what do you actually need to specify? Here's the hierarchy of decisions.

### 1. The Field ($\mathbb{F}_p$)

This is usually not your choice—it's dictated by your proof system. Each ZK system operates over a specific prime field:

| Proof System | Prime Field | Size |
|--------------|-------------|------|
| Groth16 on BN254 | BN254 scalar field | ~254 bits |
| PLONK on BLS12-381 | BLS12-381 scalar field | ~255 bits |
| STARKs (various) | Goldilocks ($2^{64} - 2^{32} + 1$) | 64 bits |
| Polygon zkEVM | BN254 scalar field | ~254 bits |

Your Poseidon parameters must match this field. Using BN254 parameters with a BLS12-381 circuit won't work—the round constants and security analysis are field-specific.

### 2. The S-Box Exponent ($\alpha$)

Usually $\alpha = 5$. The requirement is $\gcd(\alpha, p-1) = 1$ (so the S-box is invertible). For most common prime fields, 5 works. Some fields require $\alpha = 7$ or other values. Check your library's documentation.

**Heuristic**: Just use 5 unless your library says otherwise.

### 3. State Width ($t$) and Rate/Capacity Split

This is your main design decision. The state has $t$ field elements, split into:
- **Rate ($r$)**: How many elements you absorb/squeeze per permutation call
- **Capacity ($c$)**: Security buffer, never directly exposed

The relationship: $t = r + c$.


**Intuition**: Think of the state as a bucket with $t$ slots. The rate slots are the "public interface"—you pour inputs in and read outputs out through them. The capacity slots are "hidden plumbing"—they participate in the mixing but you never directly touch them.


**TL;DR**:
- **Rate ($r$)** = how many field elements you can input/output per permutation. Want to hash 2 elements? Use $r = 2$. Want to hash 4? Use $r = 4$.
- **Capacity ($c$)** = hidden state that makes the hash secure. It's not about inputs or outputs—it's the "secret sauce" that prevents attackers from inverting the hash. More capacity = more security, but also larger state = more constraints.

```
State with t=3, rate=2, capacity=1:

┌─────────┬─────────┬─────────┐
│  slot 0 │  slot 1 │  slot 2 │
│  (rate) │  (rate) │  (cap)  │
└─────────┴─────────┴─────────┘
     ↑          ↑         ╳
   input     input     hidden
   here      here      (never touched directly)
```

**Example**: Suppose you want to hash two field elements $a$ and $b$ into one output.

1. **Initialize**: State = $(0, 0, 0)$
2. **Absorb**: Add inputs to rate portion: State = $(0 + a, 0 + b, 0) = (a, b, 0)$
3. **Permute**: Apply $\pi$: State = $(\pi_0, \pi_1, \pi_2)$ — all three slots are now scrambled together
4. **Squeeze**: Read from rate portion: Output = $\pi_0$ (or $(\pi_0, \pi_1)$ if you need two outputs)

The capacity slot ($\pi_2$) got mixed with everything but was never exposed. An attacker who sees only the output $\pi_0$ can't easily work backwards because they don't know $\pi_2$.

Why does capacity provide security? If an attacker wants to find a collision (two different inputs that produce the same output), they'd need to find inputs where the *entire* post-permutation state collides, not just the rate portion. With $c$ capacity elements in a field of size $p$, that's roughly $p^c$ possible hidden states—a 255-bit field with $c=1$ gives $2^{255}$ possibilities.


**How to choose**:

For **Merkle trees** (2-to-1 compression): You need to input 2 elements and output 1. Use $t = 3$ with rate $r = 2$ and capacity $c = 1$. This is the most common configuration.

For **higher-arity trees** (4-to-1): Use $t = 5$ with $r = 4$, $c = 1$.

For **general hashing** (variable-length input): Larger state widths like $t = 9$ or $t = 12$ absorb more data per permutation, reducing the number of permutation calls for long inputs.

**Security constraint**: The capacity determines collision resistance. For $M$-bit security, you need $c \cdot \log_2(p) \geq 2M$. With a 255-bit field and 128-bit security target:
$$c \geq \frac{2 \times 128}{255} \approx 1.0$$

So $c = 1$ is the minimum for 128-bit security in a 255-bit field. For extra margin, use $c = 2$.

### 4. Round Counts ($R_F$, $R_P$)

These determine security against cryptanalytic attacks. The good news: you almost never compute these yourself. Use the values from the Poseidon paper or your library's presets.

**The standard recipe**:
- $R_F = 8$ (full rounds)—this is nearly universal
- $R_P$ depends on $t$, field size, and security level—typically 56–60 for 128-bit security

If you must compute $R_P$ yourself, the Poseidon paper provides scripts and formulas. But in practice, use a well-vetted parameter set.

### 5. Round Constants and MDS Matrix


These are derived deterministically from the other parameters. Given $(p, t, \alpha, R_F, R_P)$, the constants are computed by hashing a canonical seed.

How can we "hash" to generate constants without circular dependency? We use a *traditional* cryptographic primitive—this happens once, offline, when defining the Poseidon instance, not during actual Poseidon hashing. The constants need three properties:

1. **Deterministic**: Same parameters → same constants
2. **Unpredictable**: No algebraic structure an attacker can exploit
3. **Verifiable**: Anyone can recompute them (nothing up my sleeve)

One clean approach uses a **Merlin transcript** (a cryptographic sponge based on the Strobe protocol):

```rust
let mut transcript = Transcript::new(b"round-constants");
transcript.domain_sep::<F>(input_params, rounds, alpha);  // Commit to all parameters

let constants: Vec<F> = (0..num_rounds * width)
    .map(|_| transcript.round_constant())  // Squeeze field elements
    .collect();
```

The transcript is seeded with a fixed label and all the public parameters, then squeezes out field elements one by one—essentially a CSPRNG keyed by the parameters.

**Why Merlin instead of raw SHA3/SHAKE?** Merlin is designed for exactly this use case: deriving multiple field elements from structured inputs with proper domain separation. With raw SHA3, you'd need to manually handle encoding parameters into bytes, domain separation (so different parameter sets don't collide), extracting arbitrary-length output, and reducing bytes to field elements without bias. Merlin handles all of this with a clean API.

You never choose constants manually; your library generates them (or ships pre-computed tables for common configurations).

### Putting It Together: A Decision Flowchart

```
What proof system are you using?
    → This fixes p (the field)

What's your use case?
    → 2-to-1 Merkle: t=3, r=2, c=1
    → 4-to-1 Merkle: t=5, r=4, c=1
    → Variable-length hashing: t=9 or t=12, c=1 or c=2

What security level?
    → 128-bit (standard): use paper's recommended R_F, R_P
    → 256-bit (paranoid): double R_P

Look up or generate:
    → Round constants, MDS matrix for your (p, t, α, R_F, R_P)
```

### Example: Configuring Poseidon for a Merkle Tree in Groth16

You're building a Merkle tree proof using Groth16 on BN254:

1. **Field**: BN254 scalar field (fixed by Groth16)
2. **S-box**: $\alpha = 5$ (standard for this field)
3. **State**: $t = 3$ (rate 2 for two children, capacity 1)
4. **Rounds**: $R_F = 8$, $R_P = 57$ (from Poseidon paper for BN254, $t=3$, 128-bit security)
5. **Constants**: Use the standard BN254-Poseidon-t3 constants (your library provides these)

In circom, this might look like:
```
include "poseidon.circom";

template MerkleHash() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);  // rate = 2
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}
```

The library handles the rest—round constants, MDS matrix, and the actual permutation logic.

---

## Poseidon in Practice: Merkle Trees

The killer application for Poseidon is Merkle trees in zero-knowledge proofs. Let's trace through how this works.

### The Standard Setup

A Merkle tree with $2^d$ leaves uses $d$ hash invocations to prove membership. Each hash takes two child nodes and produces a parent. With traditional 2-to-1 hashing, the Poseidon state is:

$$\text{state} = (x_0, x_1, x_2) \quad \text{where } x_0, x_1 = \text{children}, \quad x_2 = \text{capacity}$$

After absorbing both children and squeezing, you get the parent hash. The rate is 2 (two inputs), and the capacity is 1 (internal security buffer).

### Constraint Comparison

For a depth-20 Merkle tree (about 1 million leaves):

| Hash Function | Constraints per Hash | Total Constraints |
|---------------|---------------------|-------------------|
| SHA-256 | ~25,000 | ~500,000 |
| Poseidon | ~160 | ~3,200 |

That's **156× fewer constraints**. In practice, this translates to:
- Proof generation that's 10–100× faster
- Proofs that are smaller (fewer constraints often mean less data)
- Lower memory requirements during proof generation

### Real-World Deployment

Poseidon is used in production systems:

- **Zcash Orchard**: The shielded transaction protocol uses Poseidon for Merkle tree hashing, replacing Pedersen hashes used in earlier versions.

- **StarkNet**: Uses Poseidon for state commitments and transaction validation.

- **Filecoin**: Uses Poseidon in Proof of Replication circuits.

- **Polygon zkEVM**: Uses Poseidon for various commitments in the zkEVM circuit.

- **Scroll**: Their zkEVM uses Poseidon for state hashing.

The common thread: anywhere a ZK proof needs to verify hash computations, Poseidon offers massive efficiency gains.

---

## Poseidon2: The Next Generation

Released in 2023, Poseidon2 improves on the original in several ways.

### Cheaper Internal Diffusion

The original Poseidon uses a dense MDS matrix for diffusion. While MDS matrices are "free" in constraints, they're expensive in *native* computation (when generating witnesses or running outside a circuit). An $t \times t$ MDS matrix requires $t^2$ multiplications.

Poseidon2 introduces a structured diffusion layer:
1. Apply a sparse "internal" matrix in partial rounds
2. Apply the full MDS only in full rounds

The sparse matrix has the form:
$$M_I = \begin{pmatrix} \mu & 1 & 1 & \cdots & 1 \\ 1 & 1 & 0 & \cdots & 0 \\ 1 & 0 & 1 & \cdots & 0 \\ \vdots & & & \ddots & \\ 1 & 0 & 0 & \cdots & 1 \end{pmatrix}$$

This requires only $O(t)$ operations instead of $O(t^2)$. For large state sizes, native computation speeds up significantly.

### External Round Optimization

Poseidon2 also restructures the external (full) rounds, further reducing native computation time without increasing constraint count.

### The Trade-off

Poseidon2 maintains the same constraint count as Poseidon (same security, same number of S-boxes), but proof generation is faster because witness computation (the "native" work done before proving) is cheaper.

| Metric | Poseidon | Poseidon2 |
|--------|----------|-----------|
| Constraints | ~160 | ~160 |
| Native hashes/sec | ~300K | ~1M+ |
| Memory | Similar | Similar |

If you're doing thousands of hashes per proof, Poseidon2's 3× native speedup matters.

---

## The Algebraic Hash Family Tree

Poseidon isn't the only arithmetic-friendly hash. Here's how it relates to alternatives:

### MiMC

An earlier design (2016) using extremely simple rounds:
$$x \leftarrow (x + c_i)^3$$

Just one S-box per round, repeated many times (~320 rounds for 128-bit security). Very simple, but:
- High multiplicative depth (problematic for some proof systems)
- Vulnerable to algebraic attacks with fewer rounds than originally claimed

MiMC is largely superseded by Poseidon.

### Rescue

Uses alternating S-box and inverse S-box layers:
$$x \leftarrow x^\alpha \quad \text{then} \quad x \leftarrow x^{1/\alpha}$$

The inverse S-box is expensive in native computation but "free" in some ZK systems. Good for specific proof systems; less universal than Poseidon.

### Griffin

A newer design (2022) with a more complex nonlinear layer that provides security with fewer rounds. Still being analyzed.

### Anemoi

Designed for specific prime fields (like the Jubjub curve's scalar field). Uses a structure tailored to the field's properties.

### When to Use What

| Proof System | Recommended Hash |
|--------------|------------------|
| Groth16 (R1CS) | Poseidon or Poseidon2 |
| PLONK-style | Poseidon2 |
| STARKs | Poseidon2 or Rescue-Prime |
| General purpose | Poseidon2 |

Poseidon and Poseidon2 are the safe defaults. The others serve niche applications.

---

## Security Considerations

### What Poseidon Isn't

Poseidon is designed for one specific use case: efficient hashing inside arithmetic circuits. It's **not** designed for:

- **General-purpose hashing**: For hashing files, passwords, or data at rest, use SHA-256, BLAKE3, or similar. Poseidon would work, but it's slower and less analyzed for those use cases.

- **Password hashing**: Use Argon2id. Poseidon has no memory-hardness.

- **MACs or PRFs outside ZK**: While Poseidon-based MACs exist, traditional constructions (HMAC, AES-GCM) are better analyzed for these applications.

### Known Attacks and Analysis

Poseidon has received significant cryptanalysis:

- **Grassi et al. (2019)**: Original design paper with security analysis.
- **Beierle et al. (2020)**: Algebraic attack improvements, leading to increased round counts in some configurations.
- **Ashur & Dhooghe (2021)**: Analysis of MDS matrix properties.
- **Keller & Rosemarin (2021)**: Gröbner basis attack improvements.

The current recommended parameters (with $R_F = 8$ and $R_P$ as specified) include security margins that account for these attacks. No practical attacks exist against properly configured Poseidon.

### Side-Channel Considerations

In native implementations (outside a ZK circuit), Poseidon's data-dependent operations (multiplications, the S-box) could leak timing information. For most ZK applications, this doesn't matter—you're proving you know a hash preimage, not keeping the preimage secret from a local attacker. If you do need side-channel resistance, constant-time implementations exist.

---

## Implementation Notes

### Field Selection

Poseidon parameters depend on the field. You can't use parameters designed for one prime with a different prime. Common fields:

- **BN254 scalar field**: $p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$
- **BLS12-381 scalar field**: $p = 52435875175126190479447740508185965837690552500527637822603658699938581184513$
- **Ed25519 scalar field**: $p = 2^{252} + 27742317777372353535851937790883648493$

Each field needs its own round constants and security analysis.

### Computing Round Constants

Round constants are derived deterministically from a seed using a cryptographic hash (like SHA-256). The standard approach:

```
seed = "Poseidon_BN254_t3_RF8_RP56"
for i in 0..num_rounds:
    for j in 0..t:
        constants[i][j] = hash_to_field(seed || i || j)
```

This ensures nothing-up-my-sleeve constants. Anyone can verify the constants by rerunning the derivation.

### Reference Implementations

Production-quality implementations exist in multiple languages:

- **Rust**: `poseidon-rs`, `neptune` (used in Filecoin)
- **circom**: Built-in Poseidon gadgets
- **Go**: Various zkEVM implementations
- **Cairo**: Native support in StarkNet

When implementing yourself, the biggest pitfalls are:
1. Wrong round constants for your field
2. Incorrect number of rounds
3. Off-by-one errors in the partial round indexing

Use reference test vectors and compare against known implementations.

---

## Summary

The story of Poseidon is one of matching tools to domains:

**The problem**: Traditional hash functions like SHA-256 are designed for CPUs, using bit operations that are expensive in arithmetic circuits. Proving hash computations in ZK systems costs 25,000+ constraints per hash.

**The insight**: Design a hash function using only native field operations—addition and multiplication. No bits, no XOR, no rotations.

**The solution**: Poseidon—a sponge construction with a HADES-based permutation. Full rounds provide statistical security; partial rounds provide algebraic security. The S-box is simple field exponentiation ($x^5$). The diffusion is an MDS matrix.

**The result**: ~160 constraints per hash. A 150× improvement over SHA-256 in circuits.

**The applications**: Merkle trees, nullifier derivation, signature schemes, and any ZK computation involving hashing.

Poseidon isn't a replacement for SHA-256 or BLAKE3 in general computing. It's a specialized tool for a specialized domain. But in that domain—proving hash computations inside zero-knowledge proofs—it's the difference between feasible and impractical.

---

## References

- Grassi, L., Khovratovich, D., Rechberger, C., Roy, A., & Schofnegger, M. (2019). Poseidon: A New Hash Function for Zero-Knowledge Proof Systems. *USENIX Security 2021*.
- Grassi, L., Khovratovich, D., Lüftenegger, R., Rechberger, C., Schofnegger, M., & Walch, R. (2023). Poseidon2: A Faster Version of the Poseidon Hash Function. *IACR Cryptology ePrint Archive*.
- Albrecht, M., Grassi, L., Rechberger, C., Roy, A., & Tiessen, T. (2016). MiMC: Efficient Encryption and Cryptographic Hashing with Minimal Multiplicative Complexity. *ASIACRYPT 2016*.
- Aly, A., Ashur, T., Ben-Sasson, E., Dhooghe, S., & Szepieniec, A. (2020). Design of Symmetric-Key Primitives for Advanced Cryptographic Protocols. *IACR Transactions on Symmetric Cryptology*.
- [Zcash Orchard Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [StarkNet Documentation](https://docs.starknet.io/)
- [Poseidon Reference Implementation (Rust)](https://github.com/filecoin-project/neptune)
