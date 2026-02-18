# 009: Blake2b Transcript + AST Generalization — Detailed Implementation Guide

This document contains **everything** needed to implement task 009: byte-level operations, method-by-method mapping, exact code locations, and Go-side implementation details.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Blake2b Concrete Transcript — Byte-Level Reference](#2-blake2b-concrete-transcript)
3. [Poseidon Concrete Transcript — Byte-Level Reference](#3-poseidon-concrete-transcript)
4. [Side-by-Side Method Comparison](#4-side-by-side-method-comparison)
5. [PoseidonAstTranscript — Symbolic Reference Implementation](#5-poseidonasttranscript)
6. [Current Poseidon-Specific AST Nodes](#6-current-poseidon-specific-ast-nodes)
7. [Current Gnark Codegen Mapping](#7-current-gnark-codegen-mapping)
8. [Go-Side Poseidon Hints — Full Reference](#8-go-side-poseidon-hints)
9. [Phase 1: Generalize AST Nodes](#9-phase-1-generalize-ast-nodes)
10. [Phase 2: Update Poseidon Pipeline (No Regression)](#10-phase-2-update-poseidon-pipeline)
11. [Phase 3: Blake2bAstTranscript Implementation](#11-phase-3-blake2basttranscript)
12. [Phase 4: Blake2b Gnark Codegen + Go Hints](#12-phase-4-blake2b-gnark-codegen)
13. [Phase 5: Feature Flags + CLI + Testing](#13-phase-5-feature-flags-cli-testing)
14. [Thread-Local Mechanism](#14-thread-local-mechanism)
15. [Critical Byte-Order Rules](#15-critical-byte-order-rules)
16. [Checklist](#16-checklist)

---

## 1. Architecture Overview

```
                          CURRENT (Poseidon only)
┌──────────────────────┐     ┌───────────────────────┐     ┌──────────────────┐
│ PoseidonTranscript   │     │ PoseidonAstTranscript │     │ gnark_codegen.rs │
│ (jolt-core, concrete)│     │ (transpiler, symbolic)│     │ Node → Go code   │
│                      │     │                       │     │                  │
│ hash_bytes32_and_    │ ──▶ │ hash_and_update()     │ ──▶ │ poseidon.Hash()  │
│   update()           │     │   MleAst::poseidon()  │     │                  │
│ challenge_bytes32()  │     │ challenge_ast()        │     │ poseidon.        │
│                      │     │   MleAst::truncate_128│     │   Truncate128()  │
└──────────────────────┘     └───────────────────────┘     └──────────────────┘

                          TARGET (Poseidon + Blake2b)
┌──────────────────────┐     ┌───────────────────────┐     ┌──────────────────┐
│ Blake2bTranscript    │     │ Blake2bAstTranscript  │     │ gnark_codegen.rs │
│ (jolt-core, concrete)│     │ (transpiler, symbolic)│     │ Node → Go code   │
│                      │     │                       │     │                  │
│ hasher().chain_      │ ──▶ │ hash_and_update()     │ ──▶ │ blake2b.Hash()   │
│   update().finalize()│     │   MleAst::blake2b()   │     │                  │
│ challenge_bytes32()  │     │ challenge_ast()        │     │ blake2b.         │
│                      │     │   MleAst::truncate_128│     │   Truncate128()  │
└──────────────────────┘     └───────────────────────┘     └──────────────────┘
```

The key insight: **Blake2b and Poseidon share the same domain separation pattern** (n_rounds + labels). They differ only in HOW the hash is computed. The AST and codegen layers need to dispatch on the hash backend; everything else is structurally identical.

---

## 2. Blake2b Concrete Transcript

**File**: `jolt-core/src/transcripts/blake2b.rs`

### State

```rust
pub struct Blake2bTranscript {
    pub state: [u8; 32],   // 256-bit running state
    n_rounds: u32,          // domain separation counter
}
```

### Internal hasher (lines 31-37)

Every hash call prepends `state || pad(n_rounds)` via `hasher()`:

```rust
fn hasher(&self) -> Blake2b256 {
    let mut packed = [0_u8; 28].to_vec();              // 28 zero bytes
    packed.append(&mut self.n_rounds.to_be_bytes().to_vec()); // 4 bytes BE
    // packed is 32 bytes: [0×28 || n_rounds_BE×4]
    Blake2b256::new()
        .chain_update(self.state)   // 32 bytes: current state
        .chain_update(&packed)      // 32 bytes: zero-padded n_rounds
    // Total prefix: 64 bytes (state + packed_rounds)
    // Caller appends data and calls .finalize()
}
```

**Critical**: `hasher()` does NOT finalize. The caller chains more data, THEN finalizes.

### update_state (lines 64-77)

```rust
fn update_state(&mut self, new_state: [u8; 32]) {
    self.state = new_state;
    self.n_rounds += 1;
}
```

### Transcript::new (lines 81-100)

```rust
fn new(label: &'static [u8]) -> Self {
    assert!(label.len() < 33);
    // Right-pad label to 32 bytes, hash it
    let hasher = if label.len() == 32 {
        Blake2b256::new().chain_update(label)
    } else {
        let zeros = vec![0_u8; 32 - label.len()];
        Blake2b256::new().chain_update(label).chain_update(zeros)
    };
    let out = hasher.finalize();
    Self { state: out.into(), n_rounds: 0 }
}
```

**Difference from Poseidon**: Blake2b::new hashes ONLY the label (no n_rounds, no hasher()). Poseidon::new does `poseidon(label, 0, 0)`.

### raw_append_label (lines 111-123)

```rust
fn raw_append_label(&mut self, label: &'static [u8]) {
    assert!(label.len() < 33);
    let hasher = if label.len() == 32 {
        self.hasher().chain_update(label)
    } else {
        let mut packed = label.to_vec();
        packed.append(&mut vec![0_u8; 32 - label.len()]);
        self.hasher().chain_update(packed)
    };
    self.update_state(hasher.finalize().into());
}
```

Computes: `blake2b(state || pad(n_rounds) || right_pad_32(label))`

### raw_append_bytes (lines 125-129)

```rust
fn raw_append_bytes(&mut self, bytes: &[u8]) {
    let hasher = self.hasher().chain_update(bytes);
    self.update_state(hasher.finalize().into());
}
```

Computes: `blake2b(state || pad(n_rounds) || bytes)`

**Critical difference from Poseidon**: Blake2b hashes ALL bytes in ONE call (no chunking). Poseidon chunks to 32 bytes and chains Poseidon hashes.

### raw_append_u64 (lines 131-137)

```rust
fn raw_append_u64(&mut self, x: u64) {
    let mut packed = [0_u8; 24].to_vec();
    packed.append(&mut x.to_be_bytes().to_vec());
    // packed: [0×24 || x_BE×8] = 32 bytes (EVM uint256 format)
    let hasher = self.hasher().chain_update(packed);
    self.update_state(hasher.finalize().into());
}
```

Same EVM-word packing as Poseidon.

### raw_append_scalar (lines 139-147)

```rust
fn raw_append_scalar<F: JoltField>(&mut self, scalar: &F) {
    let mut buf = vec![];
    scalar.serialize_uncompressed(&mut buf).unwrap();
    buf = buf.into_iter().rev().collect();  // LE → BE (byte reverse)
    self.raw_append_bytes(&buf);
}
```

Same as Poseidon: serialize LE → reverse to BE → hash. The byte-reverse is identical.

### raw_append_point (lines 149-170)

```rust
fn raw_append_point<G: CurveGroup>(&mut self, point: &G) {
    if point.is_zero() {
        self.raw_append_bytes(&[0_u8; 64]);
        return;
    }
    let aff = point.into_affine();
    // x, y: serialize_compressed(LE) → reverse to BE
    // concatenate x_BE(32) + y_BE(32) = 64 bytes
    let hasher = self.hasher().chain_update(x_bytes).chain_update(y_bytes);
    self.update_state(hasher.finalize().into());
}
```

### challenge_bytes32 (lines 57-62)

```rust
fn challenge_bytes32(&mut self, out: &mut [u8]) {
    let rand: [u8; 32] = self.hasher().finalize().into();
    out.clone_from_slice(rand.as_slice());
    self.update_state(rand);
}
```

Computes: `rand = blake2b(state || pad(n_rounds))` (no extra data). Updates state AND increments n_rounds.

This is the equivalent of Poseidon's `poseidon(state, n_rounds, 0)`.

### challenge_scalar_128_bits (lines 186-192)

```rust
fn challenge_scalar_128_bits<F: JoltField>(&mut self) -> F {
    let mut buf = vec![0u8; 16];
    self.challenge_bytes(&mut buf);  // fills 16 bytes from challenge_bytes32
    buf = buf.into_iter().rev().collect();
    F::from_bytes(&buf)
}
```

Takes first 16 bytes of hash output → reverse → interpret as LE field element. **Identical to Poseidon**.

### challenge_scalar_optimized (lines 210-215)

```rust
fn challenge_scalar_optimized<F: JoltField>(&mut self) -> F::Challenge {
    let challenge_scalar: u128 = self.challenge_u128();
    F::Challenge::from(challenge_scalar)
}
```

Gets u128 → constructs MontU128Challenge. **Identical to Poseidon**.

---

## 3. Poseidon Concrete Transcript

**File**: `jolt-core/src/transcripts/poseidon.rs`

### State

```rust
pub struct PoseidonTranscript<F: PrimeField, P: PoseidonParams<F>> {
    pub state: [u8; 32],
    pub n_rounds: u32,
}
```

### hash_bytes32_and_update (lines 126-149)

```rust
fn hash_bytes32_and_update(&mut self, bytes: &[u8]) {
    let state_f = F::from_le_bytes_mod_order(&self.state);
    let round_f = F::from(self.n_rounds as u64);
    let input_f = F::from_le_bytes_mod_order(bytes);
    let output = poseidon.hash(&[state_f, round_f, input_f]);
    // serialize output to 32 bytes LE, update state, n_rounds += 1
}
```

Width-3 Poseidon: `poseidon(state_as_F, n_rounds_as_F, data_as_F) → F`

### raw_append_bytes (lines 254-295)

```rust
fn raw_append_bytes(&mut self, bytes: &[u8]) {
    // First chunk: poseidon(state, n_rounds, chunk)
    // Remaining chunks: poseidon(prev, 0, chunk)  // chained, no n_rounds
    // Single update_state at the end
}
```

**Critical difference from Blake2b**: Poseidon chunks bytes into 32-byte pieces and chains multiple hashes. Blake2b hashes all bytes in one shot.

### challenge_bytes32 (lines 166-182)

```rust
fn challenge_bytes32(&mut self, out: &mut [u8]) {
    let output = poseidon.hash(&[state_f, round_f, zero]);
    out.copy_from_slice(&rand);
    self.update_state(rand);
}
```

---

## 4. Side-by-Side Method Comparison

| Method | Poseidon | Blake2b | Symbolic Impact |
|--------|----------|---------|-----------------|
| **new(label)** | `poseidon(pad32(label), 0, 0)` | `blake2b(pad32(label))` | Different init — node type matters |
| **raw_append_label** | `poseidon(state, n_rounds, pad32(label))` | `blake2b(state \|\| pad(n_rounds) \|\| pad32(label))` | Same structure (state, rounds, data) |
| **raw_append_bytes** | Chunk 32 bytes, chain Poseidon hashes | Single `blake2b(state \|\| pad(n_rounds) \|\| all_bytes)` | **Different**: Poseidon chunks, Blake2b doesn't |
| **raw_append_u64** | `poseidon(state, n_rounds, evm_pack(x))` | `blake2b(state \|\| pad(n_rounds) \|\| evm_pack(x))` | Same transformation on x |
| **raw_append_scalar** | serialize LE → reverse → `raw_append_bytes` | serialize LE → reverse → `raw_append_bytes` | **Identical** byte-reverse + hash |
| **raw_append_point** | serialize x,y → reverse each → `raw_append_bytes` (64 bytes, 2 chunks) | serialize x,y → reverse each → single hash (64 bytes) | Different chunking |
| **challenge_bytes32** | `poseidon(state, n_rounds, 0)` | `blake2b(state \|\| pad(n_rounds))` | Same pattern (hash with no data) |
| **challenge_scalar_128_bits** | Take 16 bytes → reverse → from_bytes | Take 16 bytes → reverse → from_bytes | **Identical** post-hash |
| **challenge_scalar_optimized** | challenge_u128 → MontU128Challenge | challenge_u128 → MontU128Challenge | **Identical** post-hash |

### Key Insight for AST Design

The operations that differ between Blake2b and Poseidon are:
1. **The hash function itself** (Poseidon 3-input vs Blake2b byte-stream)
2. **Chunking behavior** (Poseidon chunks to 32 bytes, Blake2b doesn't)
3. **Initialization** (Poseidon uses poseidon(label,0,0), Blake2b uses raw blake2b(label))

Everything AFTER the hash is identical: ByteReverse, Truncate128, Truncate128Reverse, AppendU64Transform — these are hash-agnostic.

---

## 5. PoseidonAstTranscript

**File**: `transpiler/src/symbolic_traits/poseidon.rs`

### Structure

```rust
pub struct PoseidonAstTranscript {
    state: MleAst,     // symbolic field element
    n_rounds: u32,     // concrete counter
}
```

### Key methods

| Method | What it does | AST node created |
|--------|-------------|-----------------|
| `label_to_field(label)` | Pad to 32 bytes → `bytes_to_scalar` → `MleAst::from(limbs)` | `Atom::Scalar([u64; 4])` |
| `hash_and_update(elem)` | `MleAst::poseidon(&self.state, &round, &elem)` | `Node::Poseidon(state, round, data)` |
| `challenge_ast()` | `MleAst::poseidon(&self.state, &round, &zero)` | `Node::Poseidon(state, round, 0)` |
| `append_field_elements(elems)` | First: `poseidon(state, n_rounds, e0)`, rest: `poseidon(prev, 0, ei)` | Chain of `Node::Poseidon` |
| `raw_append_bytes(bytes)` | Chunk to 32 → `bytes_to_scalar` → `append_field_elements` | Multiple `Node::Poseidon` |
| `raw_append_u64(x)` | `MleAst::append_u64_transform(from_u64(x))` → `hash_and_update` | `AppendU64Transform` + `Poseidon` |
| `raw_append_scalar(scalar)` | `take_pending_append()` → `byte_reverse` → `hash_and_update` | `ByteReverse` + `Poseidon` |
| `challenge_scalar_128_bits()` | `challenge_ast()` → `MleAst::truncate_128(hash)` → `set_pending_challenge` | `Truncate128` |
| `challenge_scalar_optimized()` | `challenge_ast()` → `MleAst::truncate_128_reverse(hash)` → `set_pending_challenge` | `Truncate128Reverse` |
| `append_serializable(data)` | Check commitment chunks → `append_field_elements` OR byte_reverse + hash | Various |

---

## 6. Current Poseidon-Specific AST Nodes

**File**: `zklean-extractor/src/mle_ast.rs`

### Node enum (lines ~288-331)

```rust
pub enum Node {
    Atom(Atom),
    Neg(Edge),
    Inv(Edge),
    Add(Edge, Edge),
    Mul(Edge, Edge),
    Sub(Edge, Edge),
    Div(Edge, Edge),
    Poseidon(Edge, Edge, Edge),      // ← Poseidon-specific
    ByteReverse(Edge),                // ← transcript helper (hash-agnostic)
    Truncate128Reverse(Edge),         // ← transcript helper (hash-agnostic)
    Truncate128(Edge),                // ← transcript helper (hash-agnostic)
    AppendU64Transform(Edge),         // ← transcript helper (hash-agnostic)
}
```

### Constructor methods on MleAst

| Method | Lines | Creates |
|--------|-------|---------|
| `MleAst::poseidon(state, rounds, data)` | 411-422 | `Node::Poseidon(e1, e2, e3)` |
| `MleAst::byte_reverse(e)` | 424-433 | `Node::ByteReverse(e)` |
| `MleAst::truncate_128_reverse(e)` | 435-445 | `Node::Truncate128Reverse(e)` |
| `MleAst::truncate_128(e)` | 447-457 | `Node::Truncate128(e)` |
| `MleAst::append_u64_transform(e)` | 468-475 | `Node::AppendU64Transform(e)` |

### Where nodes appear in mle_ast.rs (besides definition)

- **is_edge/node_constant** (~line 657): Pattern matches all 5 Poseidon nodes
- **evaluate_constant_node** (~line 695): Returns `None` for all 5 (can't evaluate symbolically)
- **fmt_node** (~line 824): Formatting for display
- **node_depth** (~line 877): Depth calculation
- **CSE** (~line 953): Common subexpression elimination handles all 5

---

## 7. Current Gnark Codegen Mapping

**File**: `transpiler/src/gnark_codegen.rs`

### Node → Go code (lines 310-334)

```rust
Node::ByteReverse(e) => {
    self.uses_poseidon = true;
    self.unary_op("poseidon.ByteReverse", e)
    // → "poseidon.ByteReverse(api, {e})"
}
Node::Truncate128Reverse(e) => {
    self.uses_poseidon = true;
    self.unary_op("poseidon.Truncate128Reverse", e)
}
Node::Truncate128(e) => {
    self.uses_poseidon = true;
    self.unary_op("poseidon.Truncate128", e)
}
Node::AppendU64Transform(e) => {
    self.uses_poseidon = true;
    self.unary_op("poseidon.AppendU64Transform", e)
}
Node::Poseidon(state, n_rounds, data) => {
    self.uses_poseidon = true;
    format!("poseidon.Hash(api, {s}, {r}, {d})")
}
```

### Import generation (line 593)

```rust
if stats.uses_poseidon {
    // Adds: "jolt-transpiler/poseidon" to imports
}
```

---

## 8. Go-Side Poseidon Hints

**File**: `transpiler/go/poseidon/poseidon.go`

### Registered hints (lines 16-21)

```go
func init() {
    solver.RegisterHint(byteReverseHint)
    solver.RegisterHint(truncate128ReverseHint)
    solver.RegisterHint(truncate128Hint)
    solver.RegisterHint(appendU64TransformHint)
}
```

### Hash (lines 39-52)

```go
func Hash(api frontend.API, in1, in2, in3 frontend.Variable) frontend.Variable {
    // Width-4 Poseidon: state = [0, in1, in2, in3]
    // Returns result[0]
}
```

This is NATIVE computation — Poseidon is computed in-circuit with ~250 constraints. NOT a hint.

### ByteReverse (lines 149-188)

Uses a hint:
1. Converts field element to 32-byte LE
2. Reverses all 32 bytes
3. Interprets reversed as LE → field element

### Truncate128 (lines 288-336)

Uses a hint:
1. Converts to 32-byte LE
2. Takes first 16 bytes
3. Reverses 16 bytes
4. Interprets as LE → field element (NO mask, NO shift)

### Truncate128Reverse (lines 194-280)

Uses a hint:
1. Converts to 32-byte LE
2. Takes first 16 bytes, reverses
3. Interprets as BE u128
4. Applies 125-bit mask (MontU128Challenge)
5. Computes `(low * 2^128 + high * 2^192) * R^-1 mod p`

### AppendU64Transform (lines 353-388)

Uses a hint:
1. Extract u64 value
2. Pack into `[0×24 || x_BE×8]` (32 bytes)
3. Interpret 32 bytes as LE → field element
4. Result = `bswap64(x) * 2^192`

---

## 9. Phase 1: Generalize AST Nodes

### What Stays Generic, What's Backend-Specific

| Operation | Backend-specific? | Reason |
|-----------|-------------------|--------|
| Hash computation | **YES** | Poseidon(3 field elems) vs Blake2b(byte stream) |
| ByteReverse | **NO** | Both transcripts byte-reverse scalars identically |
| Truncate128 | **NO** | Both transcripts truncate challenges identically |
| Truncate128Reverse | **NO** | Both transcripts use MontU128Challenge identically |
| AppendU64Transform | **NO** | Both transcripts pack u64 identically |

**Conclusion**: Only `Node::Poseidon` needs a backend tag. The other 4 nodes are transcript-agnostic.

### Proposed Changes to mle_ast.rs

```rust
pub enum Node {
    // ... arithmetic nodes unchanged ...

    // Backend-specific hash
    TranscriptHash(TranscriptBackend, Edge, Edge, Edge),  // For Poseidon (fixed 3-arg)
    Blake2bHash(Edge, Edge, Vec<Edge>),                    // For Blake2b (variable data)

    // Transcript-agnostic helpers (unchanged)
    ByteReverse(Edge),
    Truncate128Reverse(Edge),
    Truncate128(Edge),
    AppendU64Transform(Edge),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TranscriptBackend {
    Poseidon,
}
```

### Why Blake2b needs variable arity

Blake2b hashes ALL bytes in one shot: `blake2b(state || pad(n_rounds) || all_bytes)`. The data portion can be:
- 32 bytes (label, u64, scalar) → 1 field element
- 64 bytes (point: x+y) → 2 field elements
- 384 bytes (commitment: 12 chunks) → 12 field elements

Since `blake2b(a || b) ≠ blake2b(blake2b(a) || b)`, we CANNOT chunk and chain like Poseidon. Must pass all data fields to a single Blake2b hash call.

### Constructors

```rust
impl MleAst {
    // Keep existing — now wraps TranscriptHash
    pub fn poseidon(state: &MleAst, rounds: &MleAst, data: &MleAst) -> MleAst {
        // insert_node(Node::TranscriptHash(TranscriptBackend::Poseidon, s, r, d))
    }

    // New
    pub fn blake2b(state: &MleAst, rounds: &MleAst, data: &[MleAst]) -> MleAst {
        // insert_node(Node::Blake2bHash(s, r, data_edges))
    }
}
```

### Files to modify

1. `zklean-extractor/src/mle_ast.rs`:
   - Add `TranscriptBackend` enum
   - Rename `Node::Poseidon` → `Node::TranscriptHash(TranscriptBackend, Edge, Edge, Edge)`
   - Add `Node::Blake2bHash(Edge, Edge, Vec<Edge>)`
   - Update ~12 pattern match locations
   - Add constructors

2. `transpiler/src/gnark_codegen.rs`:
   - Match on new node variants
   - Add `uses_blake2b: bool`
   - Add blake2b import generation

---

## 10. Phase 2: Update Poseidon Pipeline (No Regression)

After Phase 1, the Poseidon pipeline must produce **identical** Go code.

### Steps

1. Save current generated `stages_circuit.go` as reference
2. Apply AST changes
3. `MleAst::poseidon()` now wraps `TranscriptHash(Poseidon, ...)` — PoseidonAstTranscript unchanged
4. Regenerate `stages_circuit.go`
5. **Diff must be empty**
6. Run `go test -v -run TestStagesCircuitProveVerify` — must pass

---

## 11. Phase 3: Blake2bAstTranscript Implementation

**File to create**: `transpiler/src/symbolic_traits/blake2b.rs`

### Structure

```rust
pub struct Blake2bAstTranscript {
    state: MleAst,     // symbolic 256-bit state
    n_rounds: u32,     // concrete counter
}
```

### Key implementation decisions

#### new(label) — Compute concretely

The label is always `&'static [u8]`, so compute the initial state with real Blake2b:

```rust
fn new(label: &'static [u8]) -> Self {
    // Concrete computation — label is constant
    let zeros = vec![0_u8; 32 - label.len()];
    let out: [u8; 32] = Blake2b256::new()
        .chain_update(label)
        .chain_update(zeros)
        .finalize().into();
    let limbs = bytes_to_scalar(&out);
    Self { state: MleAst::from(limbs), n_rounds: 0 }
}
```

No special init node needed. Initial state is a known constant.

#### hash_and_update(data) — Single field element

```rust
fn hash_and_update(&mut self, data: MleAst) {
    let round = MleAst::from_u64(self.n_rounds as u64);
    self.state = MleAst::blake2b(&self.state, &round, &[data]);
    self.n_rounds += 1;
}
```

#### hash_and_update_multi(data_fields) — Multiple field elements

```rust
fn hash_and_update_multi(&mut self, data: &[MleAst]) {
    let round = MleAst::from_u64(self.n_rounds as u64);
    self.state = MleAst::blake2b(&self.state, &round, data);
    self.n_rounds += 1;
}
```

#### challenge_ast()

```rust
fn challenge_ast(&mut self) -> MleAst {
    let round = MleAst::from_u64(self.n_rounds as u64);
    let challenge = MleAst::blake2b(&self.state, &round, &[]); // no data
    self.state = challenge;
    self.n_rounds += 1;
    challenge
}
```

#### raw_append_bytes — The critical difference

Blake2b hashes all bytes at once. Convert to field elements but pass ALL to a single Blake2b node:

```rust
fn raw_append_bytes(&mut self, bytes: &[u8]) {
    let elements: Vec<MleAst> = bytes.chunks(32)
        .map(|chunk| {
            let mut padded = [0u8; 32];
            padded[..chunk.len()].copy_from_slice(chunk);
            MleAst::from(bytes_to_scalar(&padded))
        })
        .collect();
    self.hash_and_update_multi(&elements);
}
```

#### raw_append_u64, raw_append_scalar, challenge methods

Identical to Poseidon (same AppendU64Transform, ByteReverse, Truncate128 nodes).

#### append_serializable override

Same pattern as Poseidon: check for commitment chunks, use `hash_and_update_multi` instead of `append_field_elements`.

---

## 12. Phase 4: Blake2b Gnark Codegen + Go Hints

### Go package: `transpiler/go/blake2b/blake2b.go`

Blake2b in-circuit uses hints (~50K constraints/hash) because Blake2b operates on bytes, not field elements.

```go
package blake2b

import (
    "golang.org/x/crypto/blake2b"
    "math/big"
    "github.com/consensys/gnark/constraint/solver"
    "github.com/consensys/gnark/frontend"
)

func init() {
    solver.RegisterHint(blake2bHashHint)
}

// Hash computes blake2b(state_bytes || pad(n_rounds) || data_bytes...)
func Hash(api frontend.API, state, rounds frontend.Variable, data ...frontend.Variable) frontend.Variable {
    inputs := make([]frontend.Variable, 2+len(data))
    inputs[0] = state
    inputs[1] = rounds
    copy(inputs[2:], data)
    result, err := api.Compiler().NewHint(blake2bHashHint, 1, inputs...)
    if err != nil { panic(err) }
    return result[0]
}
```

### blake2bHashHint

```go
func blake2bHashHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
    // inputs[0] = state → 32 bytes LE
    // inputs[1] = n_rounds → pack as [0×28 || n_rounds_BE×4]
    // inputs[2..] = data fields → each 32 bytes LE

    stateBytes := fieldToLE32(inputs[0])

    nRounds := inputs[1].Uint64()
    packed := [32]byte{}
    packed[28] = byte(nRounds >> 24)
    packed[29] = byte(nRounds >> 16)
    packed[30] = byte(nRounds >> 8)
    packed[31] = byte(nRounds)

    h, _ := blake2b.New256(nil)
    h.Write(stateBytes[:])
    h.Write(packed[:])

    for i := 2; i < len(inputs); i++ {
        dataBytes := fieldToLE32(inputs[i])
        h.Write(dataBytes[:])
    }

    hash := h.Sum(nil)
    outputs[0] = leToField(hash)
    return nil
}
```

### Codegen for Blake2bHash node

```rust
Node::Blake2bHash(state, rounds, data_fields) => {
    self.uses_blake2b = true;
    let s = self.edge_to_gnark(state);
    let r = self.edge_to_gnark(rounds);
    let data_args: Vec<String> = data_fields.iter()
        .map(|e| self.edge_to_gnark(e))
        .collect();
    if data_args.is_empty() {
        format!("blake2b.Hash(api, {s}, {r})")
    } else {
        format!("blake2b.Hash(api, {s}, {r}, {})", data_args.join(", "))
    }
}
```

The helper functions (ByteReverse, Truncate128, etc.) stay in the `poseidon` Go package. They're hash-agnostic — same bytes-to-field conversions regardless of backend.

---

## 13. Phase 5: Feature Flags + CLI + Testing

### lib.rs changes

```rust
#[cfg(feature = "transcript-blake2b")]
pub type SelectedAstTranscript = Blake2bAstTranscript;  // was PoseidonAstTranscript
```

### Module registration (symbolic_traits/mod.rs)

```rust
pub mod blake2b;
pub use blake2b::Blake2bAstTranscript;
```

### Testing

1. Generate proof WITHOUT `--features transcript-poseidon` (Blake2b is default)
2. Transpile with `--features transcript-blake2b`
3. `go test -v -run TestStagesCircuitProveVerify`
4. Also verify Poseidon still works (regression test)

---

## 14. Thread-Local Mechanism

Both transcripts use the same thread-local mechanism:

| Thread-local | Set by | Read by | Purpose |
|-------------|--------|---------|---------|
| `PENDING_CHALLENGE` | transcript challenge method | `MleAst::from_bytes` | Pass symbolic challenge |
| `PENDING_APPEND` | `MleAst::serialize_uncompressed` | transcript `raw_append_scalar` | Pass symbolic value |
| `PENDING_COMMITMENT_CHUNKS` | `AstCommitment::serialize` | transcript `append_serializable` | Pass 12 commitment chunks |

Hash-agnostic. Blake2bAstTranscript uses it identically.

---

## 15. Critical Byte-Order Rules

### Blake2b hasher() prefix (always 64 bytes)

```
[state_bytes (32, raw)]  [0×28 || n_rounds_BE×4 (32)]
```

### Data encoding per method

| Method | Data bytes appended after prefix |
|--------|----------------------------------|
| raw_append_label | right_pad_32(label) — 32 bytes |
| raw_append_u64 | `[0×24 \|\| x_BE×8]` — 32 bytes |
| raw_append_scalar | LE_serialize → reverse — 32 bytes |
| raw_append_point | x_BE(32) + y_BE(32) — 64 bytes |
| raw_append_bytes (commitments) | reversed serialization — variable |
| challenge_bytes32 | nothing (just prefix) — 0 bytes |

### Go hint byte conversions

Field element (big.Int) → 32 bytes LE:
```go
beBytes := x.Bytes()  // big-endian, variable length
le := [32]byte{}
for i := 0; i < len(beBytes) && i < 32; i++ {
    le[i] = beBytes[len(beBytes)-1-i]
}
```

32 bytes → field element (big.Int):
```go
be := make([]byte, 32)
for i := 0; i < 32; i++ {
    be[i] = le[31-i]
}
result := new(big.Int).SetBytes(be)
```

---

## 16. Checklist

### Phase 1: Generalize AST
- [ ] Add `TranscriptBackend` enum to `mle_ast.rs`
- [ ] Rename `Node::Poseidon` → `Node::TranscriptHash(TranscriptBackend, Edge, Edge, Edge)`
- [ ] Add `Node::Blake2bHash(Edge, Edge, Vec<Edge>)`
- [ ] Update all Node pattern matches in mle_ast.rs (~12 locations)
- [ ] Add `MleAst::blake2b(state, rounds, data_fields)` constructor
- [ ] Keep `MleAst::poseidon()` as wrapper
- [ ] `cargo check -p zklean-extractor`

### Phase 2: Poseidon No-Regression
- [ ] Save current `stages_circuit.go`
- [ ] Update `gnark_codegen.rs` to match on `TranscriptHash(Poseidon, ...)`
- [ ] Regenerate circuit — diff must be empty
- [ ] `cargo check -p transpiler`
- [ ] `go test -v -run TestStagesCircuitProveVerify` passes

### Phase 3: Blake2bAstTranscript
- [ ] Create `transpiler/src/symbolic_traits/blake2b.rs`
- [ ] Implement `Blake2bAstTranscript` struct
- [ ] Implement `Transcript` trait: new, all raw_append_*, all challenge_*
- [ ] Handle `append_serializable` override (commitment chunks)
- [ ] Add `blake2` dependency to transpiler `Cargo.toml`
- [ ] Register in `symbolic_traits/mod.rs`
- [ ] `cargo check -p transpiler --features transcript-blake2b`

### Phase 4: Go-Side Blake2b
- [ ] Create `transpiler/go/blake2b/blake2b.go`
- [ ] Implement `Hash(api, state, rounds, data...)` with hint
- [ ] Implement `blake2bHashHint`
- [ ] Register hint in `init()`
- [ ] Add blake2b dispatch in `gnark_codegen.rs`
- [ ] Add `uses_blake2b` tracking and import generation
- [ ] Update `go.mod` if needed (`golang.org/x/crypto/blake2b`)

### Phase 5: Integration
- [ ] Update `lib.rs`: `SelectedAstTranscript = Blake2bAstTranscript`
- [ ] Generate proof without `--features transcript-poseidon`
- [ ] Transpile with `--features transcript-blake2b`
- [ ] `go test -v -run TestStagesCircuitProveVerify` passes for Blake2b
- [ ] Poseidon pipeline still works (regression test)
- [ ] Document constraint count comparison

---

*Created: 2026-02-17*
*References: task 009, task 003 (absorbed)*
