# Jolt zkVM Verifier Transpilation to Gnark/Groth16: Complete Reference

## Executive Summary

This document captures all modifications made to transpile the Jolt zkVM verifier from Rust to Gnark circuits for Groth16 proof generation. The transpilation enables wrapping Jolt proofs in a constant-size 164-byte Groth16 proof for efficient on-chain verification.

**Final Results (Stages 1-5):**
| Metric | Value |
|--------|-------|
| Assertions | 13 |
| Constraints | 1,531,516 |
| Proof size | 164 bytes |
| Prove time | 3.78s |
| Verify time | 1.59ms |

**Sanity Check Results:**
- 100% rejection rate on corrupted witnesses (20/20 random fuzzing, 6/6 targeted corruptions)
- 5,924 Poseidon hash calls for Fiat-Shamir transcript
- 11,839 field multiplications, 5,833 additions

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Jolt-Core Modifications (~25 files)](#2-jolt-core-modifications-25-files)
3. [ZkLean-Extractor: The Symbolic Engine](#3-zklean-extractor-the-symbolic-engine)
4. [Gnark-Transpiler: Rust to Go Conversion](#4-gnark-transpiler-rust-to-go-conversion)
5. [Go/Gnark Circuit Implementation](#5-gognark-circuit-implementation)
6. [Stage-by-Stage Progress](#6-stage-by-stage-progress)
7. [Bugs Fixed and Lessons Learned](#7-bugs-fixed-and-lessons-learned)
8. [Commands Reference](#8-commands-reference)
9. [Files Modified Summary](#9-files-modified-summary)

---

## 1. Architecture Overview

### The Transpilation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRANSPILATION PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────┘

     Rust Verifier                  Symbolic Execution                 Gnark Circuit
    ┌─────────────┐               ┌─────────────────┐               ┌──────────────┐
    │             │               │                 │               │              │
    │  JoltField  │  ──────────▶  │     MleAst      │  ──────────▶  │   Go/Gnark   │
    │    (Fr)     │  substitute   │  (Symbolic AST) │   codegen     │   Circuit    │
    │             │               │                 │               │              │
    └─────────────┘               └─────────────────┘               └──────────────┘
          │                              │                                 │
          │                              │                                 │
          ▼                              ▼                                 ▼
    Real computation              Records all ops               R1CS constraints
    returns true/false            as AST nodes                  Groth16 proof
```

### The Three Generic Parameters

The key insight is running the **same Jolt verifier code** in two modes:

| Mode | Field Type `F` | Transcript `T` | Accumulator `A` |
|------|----------------|----------------|-----------------|
| **Normal** | `Fr` (BN254 scalar) | `PoseidonTranscript` | `VerifierOpeningAccumulator<Fr>` |
| **Symbolic** | `MleAst` (builds AST) | `PoseidonAstTranscript` | `MleOpeningAccumulator` |

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **jolt-core** | `jolt-core/src/` | Original verifier (modified for generics) |
| **zklean-extractor** | `zklean-extractor/src/` | Symbolic field `MleAst` implementation |
| **gnark-transpiler** | `gnark-transpiler/src/` | AST → Go code generation |
| **Go circuit** | `gnark-transpiler/go/` | Generated Gnark circuit + Poseidon |

---

## 2. Jolt-Core Modifications (~25 files)

### 2.1 The Core Problem

The original Jolt verifier was *partially* generic. It used `<F: JoltField>` for the field type, but hardcoded `VerifierOpeningAccumulator<F>`:

```rust
// BEFORE: Original Jolt
pub trait SumcheckInstanceVerifier<F: JoltField, T: Transcript> {
    fn input_claim(&self, accumulator: &VerifierOpeningAccumulator<F>) -> F;
    fn expected_output_claim(&self, accumulator: &VerifierOpeningAccumulator<F>, ...) -> F;
    fn cache_openings(&self, accumulator: &mut VerifierOpeningAccumulator<F>, ...);
}
```

This prevented substituting a symbolic accumulator for transpilation.

### 2.2 The Solution: Generic Accumulator

Added a third generic parameter `A: OpeningAccumulator<F>`:

```rust
// AFTER: Our Modified Version
pub trait SumcheckInstanceVerifier<F: JoltField, T: Transcript, A: OpeningAccumulator<F>> {
    fn input_claim(&self, accumulator: &A) -> F;
    fn expected_output_claim(&self, accumulator: &A, ...) -> F;
    fn cache_openings(&self, accumulator: &mut A, ...);
}
```

### 2.3 OpeningAccumulator Trait Extension

Extended the `OpeningAccumulator` trait with read+write methods:

**File**: `jolt-core/src/poly/opening_proof.rs`

```rust
pub trait OpeningAccumulator<F: JoltField>: Clone + Sync + Send {
    // Read methods (existed before)
    fn get_virtual_polynomial_opening(
        &self,
        polynomial: VirtualPolynomial,
        sumcheck_id: SumcheckId,
    ) -> (Vec<F>, F);

    fn get_committed_polynomial_opening(
        &self,
        polynomial: CommittedPolynomial,
        sumcheck_id: SumcheckId,
    ) -> (Vec<F>, F);

    // Write methods (added for symbolic execution)
    fn append_virtual<T: Transcript>(
        &mut self,
        transcript: &mut T,
        polynomial: VirtualPolynomial,
        opening_point: &[F],
        claim: &F,
        sumcheck_id: SumcheckId,
    );

    fn append_committed<T: Transcript>(
        &mut self,
        transcript: &mut T,
        polynomial: CommittedPolynomial,
        opening_point: &[F],
        claim: &F,
        sumcheck_id: SumcheckId,
    );

    // ... more append methods
}
```

### 2.4 Files Modified in jolt-core

| Directory | Files | Changes |
|-----------|-------|---------|
| `jolt-core/src/poly/` | `opening_proof.rs` | Extended `OpeningAccumulator` trait |
| `jolt-core/src/subprotocols/` | `sumcheck_verifier.rs`, `sumcheck.rs`, `univariate_skip.rs` | Added `A` generic parameter |
| `jolt-core/src/zkvm/spartan/` | `outer.rs`, `product.rs`, `shift.rs`, `instruction_input.rs`, `claim_reductions.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/ram/` | `read_write_checking.rs`, `raf_evaluation.rs`, `val_evaluation.rs`, `val_final.rs`, `ra_reduction.rs`, `hamming_booleanity.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/registers/` | `read_write_checking.rs`, `val_evaluation.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/instruction_lookups/` | `read_raf_checking.rs`, `ra_virtual.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/bytecode/` | `read_raf_checking.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/` | `transpilable_verifier.rs` | New file: orchestrates transpilation |

### 2.5 TranspilableVerifier

**File**: `jolt-core/src/zkvm/transpilable_verifier.rs`

This is the main entry point for transpilation. It instantiates the verifier with symbolic types:

```rust
pub struct TranspilableVerifier<'a, F, PCS, ProofTranscript, A>
where
    F: JoltField,
    PCS: CommitmentScheme<Field = F>,
    ProofTranscript: Transcript,
    A: OpeningAccumulator<F>,
{
    proof: &'a JoltProof<PCS>,
    preprocessing: &'a JoltPreprocessing<F, PCS>,
    transcript: ProofTranscript,
    accumulator: A,
    // ...
}

impl TranspilableVerifier<'_, MleAst, AstCommitmentScheme, PoseidonAstTranscript, MleOpeningAccumulator> {
    pub fn verify_stages(&mut self) -> Result<(), anyhow::Error> {
        self.verify_stage1()?;  // Spartan outer
        self.verify_stage2()?;  // Product, RAM RAF, Output check
        self.verify_stage3()?;  // Shift, Instruction input, Register reduction
        self.verify_stage4()?;  // Register r/w, RAM val, RAM val final
        self.verify_stage5()?;  // Register val eval, RAM Hamming, RAM ra reduction, Lookups
        // Stage 6+ pending (PCS opening)
        Ok(())
    }
}
```

### 2.6 Poseidon Transcript Support

**PR**: https://github.com/a16z/jolt/pull/1173

Added Poseidon as an optional transcript hash function for SNARK-friendly verification:

**Files**:
- `jolt-core/src/transcripts/poseidon.rs` - Generic Poseidon transcript
- `jolt-core/src/transcripts/poseidon_fq_params.rs` - Fq parameters for recursion
- `jolt-core/Cargo.toml` - Added `light-poseidon` dependency

```rust
// Generic Poseidon transcript
pub struct PoseidonTranscript<F: JoltField, P: PoseidonParams<F>> { ... }

// Concrete aliases
pub type PoseidonTranscriptFr = PoseidonTranscript<Fr, FrParams>;
pub type PoseidonTranscriptFq = PoseidonTranscript<Fq, FqParams>;
```

**Why Poseidon?** ~8x fewer constraints than SHA256/Keccak inside R1CS circuits.

---

## 3. ZkLean-Extractor: The Symbolic Engine

### 3.1 Core Concept: MleAst

**File**: `zklean-extractor/src/mle_ast.rs`

`MleAst` implements `JoltField` but instead of computing values, it builds an AST:

```rust
pub struct MleAst {
    pub root: NodeId,      // Index into global NODE_ARENA
    pub reg_name: Option<String>,
}

pub enum Node {
    Atom(Atom),                    // Scalar constant or variable
    Add(Edge, Edge),               // Addition
    Sub(Edge, Edge),               // Subtraction
    Mul(Edge, Edge),               // Multiplication
    Div(Edge, Edge),               // Division (becomes Inverse + Mul)
    Neg(Edge),                     // Negation
    Inv(Edge),                     // Multiplicative inverse
    Poseidon(Edge, Edge, Edge),    // Poseidon hash (state, rounds, data)
    Truncate128(Edge),             // Challenge derivation (batching coeffs)
    Truncate128Reverse(Edge),      // Challenge derivation (sumcheck challenges)
    Keccak256(Edge),               // Keccak hash (not used with Poseidon transcript)
    ByteReverse(Edge),             // Byte reversal
    MulTwoPow192(Edge),            // Montgomery optimization
}

pub enum Atom {
    Scalar([u64; 4]),   // Constant value
    Var(u16),           // Proof element variable
    NamedVar(usize),    // CSE-hoisted variable
}
```

### 3.2 Constraint Mode

MleAst has a special "constraint mode" for capturing verification constraints:

```rust
// Thread-local storage for constraints
thread_local! {
    static CONSTRAINT_MODE: Cell<bool> = Cell::new(false);
    static SYMBOLIC_CONSTRAINTS: RefCell<Vec<MleAst>> = RefCell::new(Vec::new());
}

pub fn enable_constraint_mode() {
    CONSTRAINT_MODE.with(|c| c.set(true));
}

pub fn take_constraints() -> Vec<MleAst> {
    SYMBOLIC_CONSTRAINTS.with(|c| c.borrow_mut().drain(..).collect())
}

// PartialEq implementation - registers constraints in constraint mode
impl PartialEq for MleAst {
    fn eq(&self, other: &Self) -> bool {
        if CONSTRAINT_MODE.with(|c| c.get()) {
            // Register (self - other) = 0 constraint
            add_constraint(self.clone() - other);
            true  // Always return true in constraint mode
        } else {
            self.root == other.root
        }
    }
}
```

### 3.3 Critical Optimizations

#### Multiply-by-Zero Short-Circuit

Prevents "constant vs constant" assertion errors in Gnark:

```rust
impl Mul for MleAst {
    fn mul(self, rhs: &Self) -> Self {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();  // Don't create Mul node
        }
        self.binop(Node::Mul, rhs)
    }
}
```

#### Add-by-Zero / Subtract-Zero Identity

Reduces AST size:

```rust
impl Add for MleAst {
    fn add(mut self, rhs: &Self) -> Self::Output {
        if self.is_zero() { return rhs.clone(); }  // 0 + x = x
        if rhs.is_zero() { return self; }          // x + 0 = x
        self.binop(Node::Add, rhs)
    }
}

impl Sub for MleAst {
    fn sub(mut self, rhs: &Self) -> Self::Output {
        if rhs.is_zero() { return self; }           // x - 0 = x
        if self.is_zero() { return -rhs.clone(); }  // 0 - x = -x
        self.binop(Node::Sub, rhs)
    }
}
```

#### is_one() Fix (Critical Bug)

The default `One::is_one()` implementation uses `==`, which triggered spurious constraints:

```rust
// BEFORE: Default implementation caused spurious constraints
fn is_one(&self) -> bool {
    *self == Self::one()  // Triggers PartialEq::eq → adds constraint!
}

// AFTER: Direct node inspection
impl One for MleAst {
    fn is_one(&self) -> bool {
        matches!(
            get_node(self.root),
            Node::Atom(Atom::Scalar(value)) if value == SCALAR_ONE
        )
    }
}
```

### 3.4 Helper Methods for Code Generation

```rust
impl MleAst {
    /// Create from existing node ID
    pub fn from_node_id(node_id: NodeId) -> Self {
        Self { root: node_id, reg_name: None }
    }

    /// Check if AST has no variables (all constants)
    pub fn is_constant(&self) -> bool {
        is_node_constant(self.root)
    }

    /// Evaluate constant expression
    pub fn try_evaluate_constant(&self) -> Option<[u64; 4]> {
        if !self.is_constant() { return None; }
        Some(evaluate_constant_node(self.root))
    }
}
```

### 3.5 Transcript Tunneling

The `Transcript` trait calls `F::serialize()` internally, which doesn't make sense for AST nodes. We use thread-local storage to "tunnel" the value:

```rust
thread_local! {
    static LAST_SERIALIZED: RefCell<Option<MleAst>> = RefCell::new(None);
}

impl CanonicalSerialize for MleAst {
    fn serialize_uncompressed(&self, _writer: impl Write) -> Result<(), ...> {
        // Store in thread-local instead of writing bytes
        LAST_SERIALIZED.with(|cell| {
            *cell.borrow_mut() = Some(self.clone());
        });
        Ok(())
    }
}

// In PoseidonAstTranscript::append_scalar:
fn append_scalar(&mut self, scalar: &MleAst) {
    scalar.serialize_uncompressed(&mut Vec::new()).unwrap();
    let ast = LAST_SERIALIZED.with(|cell| cell.borrow_mut().take()).unwrap();
    // Now we have the MleAst to work with
}
```

---

## 4. Gnark-Transpiler: Rust to Go Conversion

### 4.1 Main Entry Point

**File**: `gnark-transpiler/src/bin/transpile_stages.rs`

```rust
fn main() {
    // Load proof, preprocessing, io_device
    let proof = load_proof("/tmp/fib_proof.bin");
    let preprocessing = load_preprocessing("/tmp/jolt_verifier_preprocessing.dat");

    // Symbolize proof elements (assign variable indices)
    let (symbolic_proof, accumulator, var_alloc) = symbolize_proof(&proof);

    // Create transpilable verifier with symbolic types
    let mut verifier = TranspilableVerifier::<
        MleAst,
        AstCommitmentScheme,
        PoseidonAstTranscript,
        MleOpeningAccumulator,
    >::new(&symbolic_proof, &preprocessing);

    // Run verification (builds AST + collects constraints)
    enable_constraint_mode();
    verifier.verify_stages().expect("Verification failed");
    let constraints = take_constraints();

    // Generate Go circuit code
    let circuit_code = generate_circuit_from_bundle(&bundle, "JoltStages16Circuit");
    std::fs::write("go/stages16_circuit.go", circuit_code)?;

    // Generate witness JSON
    let witness = extract_witness_values(&proof, &var_alloc);
    std::fs::write("go/stages16_witness.json", witness)?;
}
```

### 4.2 Code Generation

**File**: `gnark-transpiler/src/codegen.rs`

#### MemoizedCodeGen with Per-Constraint CSE

```rust
pub struct MemoizedCodeGen {
    ref_counts: HashMap<usize, usize>,      // Reference counting for CSE
    generated: HashMap<usize, String>,       // NodeId → Go variable name
    bindings: Vec<String>,                   // CSE variable definitions
    cse_counter: usize,                      // Next CSE variable index
    vars: BTreeSet<u16>,                     // Collected input variables
    var_names: HashMap<u16, String>,         // Variable index → name
    constraint_idx: Option<usize>,           // Per-constraint CSE namespace
}

impl MemoizedCodeGen {
    /// Generate CSE variable name with constraint prefix
    fn make_cse_name(&self) -> String {
        match self.constraint_idx {
            Some(idx) => format!("cse_{}_{}", idx, self.cse_counter),
            None => format!("cse_{}", self.cse_counter),
        }
    }
}
```

#### Iterative AST Traversal (Stack Overflow Fix)

Stage 5's deep AST caused stack overflow with recursive traversal. Fixed with iterative implementation:

```rust
pub fn generate_expr(&mut self, root_node_id: usize) -> String {
    // Phase 1: Build post-order traversal (children before parents)
    let mut post_order: Vec<usize> = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut stack: Vec<(usize, bool)> = vec![(root_node_id, false)];

    while let Some((node_id, children_processed)) = stack.pop() {
        if children_processed {
            post_order.push(node_id);
            continue;
        }
        if visited.contains(&node_id) { continue; }
        visited.insert(node_id);
        stack.push((node_id, true));

        // Push children
        let node = get_node(node_id);
        match node {
            Node::Add(e1, e2) | Node::Mul(e1, e2) | ... => {
                if let Edge::NodeRef(id) = e2 { stack.push((id, false)); }
                if let Edge::NodeRef(id) = e1 { stack.push((id, false)); }
            }
            // ... other node types
        }
    }

    // Phase 2: Generate expressions in post-order
    for node_id in post_order {
        if self.generated.contains_key(&node_id) { continue; }

        let expr = match get_node(node_id) {
            Node::Add(l, r) => format!("api.Add({}, {})",
                self.edge_to_gnark_iterative(l),
                self.edge_to_gnark_iterative(r)),
            Node::Mul(l, r) => format!("api.Mul({}, {})", ...),
            Node::Poseidon(s, r, d) => format!("poseidon.Hash(api, {}, {}, {})", ...),
            // ... other nodes
        };

        // Hoist to CSE variable if referenced multiple times
        let ref_count = self.ref_counts.get(&node_id).copied().unwrap_or(1);
        if ref_count > 1 {
            let var_name = self.make_cse_name();
            self.cse_counter += 1;
            self.bindings.push(format!("\t{} := {}\n", var_name, expr));
            self.generated.insert(node_id, var_name);
        } else {
            self.generated.insert(node_id, expr);
        }
    }

    self.generated.get(&root_node_id).cloned().unwrap()
}
```

#### Constant Assertion Detection

Skip statically-verified assertions:

```rust
pub fn generate_circuit_from_bundle_with_stats(
    bundle: &AstBundle,
    circuit_name: &str,
) -> (String, ConstantAssertionStats) {
    for (name, expr, assertion) in constraints {
        let is_const = MleAst::from_node_id(expr).is_constant();

        if is_const {
            if let Some(val) = try_evaluate_constant(expr) {
                if val == [0, 0, 0, 0] {
                    // Statically verified - skip emission
                    output.push_str(&format!("\t// {} = 0 (statically verified, skipped)\n", name));
                    stats.constant_skipped += 1;
                    continue;
                }
            }
        }

        // Emit normal constraint
        output.push_str(&format!("\t{} := {}\n", name, expr));
        output.push_str(&format!("\tapi.AssertIsEqual({}, 0)\n", name));
    }
}
```

### 4.3 MleOpeningAccumulator

**File**: `gnark-transpiler/src/mle_opening_accumulator.rs`

Symbolic version of `VerifierOpeningAccumulator`:

```rust
pub struct MleOpeningAccumulator {
    openings: HashMap<(VirtualPolynomial, SumcheckId), (Vec<MleAst>, MleAst)>,
    committed_openings: HashMap<(CommittedPolynomial, SumcheckId), (Vec<MleAst>, MleAst)>,
}

impl OpeningAccumulator<MleAst> for MleOpeningAccumulator {
    fn append_virtual<T: Transcript>(
        &mut self,
        transcript: &mut T,
        polynomial: VirtualPolynomial,
        opening_point: &[MleAst],
        claim: &MleAst,
        sumcheck_id: SumcheckId,
    ) {
        // CRITICAL: Must append claim to transcript (matches real accumulator)
        transcript.append_scalar(claim);

        self.openings.insert(
            (polynomial, sumcheck_id),
            (opening_point.to_vec(), claim.clone()),
        );
    }

    // ... similar for other append methods
}
```

### 4.4 PoseidonAstTranscript

**File**: `gnark-transpiler/src/poseidon_transcript.rs`

Symbolic transcript that builds Poseidon AST nodes:

```rust
pub struct PoseidonAstTranscript {
    state: MleAst,
    n_rounds: usize,
}

impl Transcript for PoseidonAstTranscript {
    fn append_scalar(&mut self, scalar: &MleAst) {
        // Build Poseidon(state, n_rounds, scalar) AST node
        self.state = MleAst::poseidon(&self.state, self.n_rounds, scalar);
    }

    fn challenge_scalar(&mut self) -> MleAst {
        // Truncate128 for batching coefficients
        MleAst::truncate128(&self.state)
    }

    fn challenge_scalar_optimized(&mut self) -> MleAst {
        // Truncate128Reverse for sumcheck challenges
        MleAst::truncate128_reverse(&self.state)
    }
}
```

---

## 5. Go/Gnark Circuit Implementation

### 5.1 Generated Circuit Structure

**File**: `gnark-transpiler/go/stages16_circuit.go` (auto-generated)

```go
package jolt_verifier

import (
    "math/big"
    "github.com/consensys/gnark/frontend"
    "jolt_verifier/poseidon"
)

func bigInt(s string) *big.Int {
    n, _ := new(big.Int).SetString(s, 10)
    return n
}

type JoltStages16Circuit struct {
    // Commitments (41 × 12 = 492 fields)
    Commitment_0_0 frontend.Variable `gnark:",public"`
    Commitment_0_1 frontend.Variable `gnark:",public"`
    // ... ~1200 public inputs total

    // Virtual claims
    Claim_Virtual_PC_SpartanOuter frontend.Variable `gnark:",public"`
    Claim_Virtual_Rs1Value_SpartanOuter frontend.Variable `gnark:",public"`
    // ...

    // Committed claims
    Claim_Committed_RdInc_RegistersReadWriteChecking frontend.Variable `gnark:",public"`
    // ...
}

func (circuit *JoltStages16Circuit) Define(api frontend.API) error {
    // CSE bindings for constraint 0
    cse_0_0 := poseidon.Hash(api, circuit.Commitment_0_0, ...)
    cse_0_1 := api.Add(cse_0_0, ...)
    // ...

    // CSE bindings for constraint 1
    cse_1_0 := poseidon.Hash(api, ...)
    // ...

    // 13 assertions
    a0 := api.Sub(cse_0_42, api.Mul(cse_0_43, circuit.BatchingCoeff0))
    api.AssertIsEqual(a0, 0)

    a1 := api.Sub(cse_1_35, api.Mul(cse_1_36, cse_1_37))
    api.AssertIsEqual(a1, 0)

    // ... through a12

    return nil
}
```

### 5.2 Poseidon Implementation

**File**: `gnark-transpiler/go/poseidon/poseidon.go`

Hand-written Poseidon hash matching Jolt's `light-poseidon`:

```go
package poseidon

import "github.com/consensys/gnark/frontend"

// MDS matrix (4x4 for width=4)
var MDS = [4][4]string{
    {"...", "...", "...", "..."},
    // ...
}

// Round constants (8 full + 56 partial rounds)
var ROUND_CONSTANTS = []string{...}

func Hash(api frontend.API, state, nRounds, data frontend.Variable) frontend.Variable {
    // Add data to state
    s := [4]frontend.Variable{
        api.Add(state, data),
        0, 0, 0,
    }

    // Full rounds
    for r := 0; r < 4; r++ {
        // S-box (x^5)
        for i := 0; i < 4; i++ {
            s[i] = sbox(api, s[i])
        }
        // MDS
        s = mds(api, s)
        // Add round constants
        for i := 0; i < 4; i++ {
            s[i] = api.Add(s[i], ROUND_CONSTANTS[r*4+i])
        }
    }

    // Partial rounds
    for r := 0; r < 56; r++ {
        s[0] = sbox(api, s[0])  // Only first element
        s = mds(api, s)
        s[0] = api.Add(s[0], ROUND_CONSTANTS[16+r])
    }

    // Final full rounds
    // ...

    return s[0]
}

func Truncate128(api frontend.API, hash frontend.Variable) frontend.Variable {
    // Extract low 128 bits
    bits := api.ToBinary(hash, 256)
    return api.FromBinary(bits[:128]...)
}

func Truncate128Reverse(api frontend.API, hash frontend.Variable) frontend.Variable {
    // Extract low 128 bits, reverse, shift by 2^192
    bits := api.ToBinary(hash, 256)
    reversed := reverseBits(bits[:128])
    low := api.FromBinary(reversed...)
    return api.Mul(low, bigInt("6277101735386680763835789423207666416102355444464034512896"))
}
```

### 5.3 Sanity Check Tests

**File**: `gnark-transpiler/go/stages16_circuit_test.go`

```go
// TestCorruptedWitnessRejected - Verifies corrupted witnesses are rejected
func TestCorruptedWitnessRejected(t *testing.T) {
    testCases := []struct {
        name      string
        fieldName string
    }{
        {"Corrupt commitment", "Commitment_0_0"},
        {"Corrupt PC claim", "Claim_Virtual_PC_SpartanOuter"},
        {"Corrupt Rs1 value", "Claim_Virtual_Rs1Value_SpartanOuter"},
        // ...
    }

    for _, tc := range testCases {
        assignment := LoadWitness()
        CorruptField(assignment, tc.fieldName)
        err := test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
        if err == nil {
            t.Fatalf("CRITICAL: %s was NOT rejected!", tc.name)
        }
    }
}

// TestRandomFuzzing - 20 random field corruptions
func TestRandomFuzzing(t *testing.T) {
    // 100% rejection rate achieved
}

// TestAssertionCountMatchesTheory - Verify 13 assertions
func TestAssertionCountMatchesTheory(t *testing.T) {
    // Count AssertIsEqual calls in circuit
    // Verify matches expected sumcheck structure
}

// TestCircuitNotTrivial - Verify substantial computation
func TestCircuitNotTrivial(t *testing.T) {
    // 1,531,516 constraints
    // 5,924 Poseidon hashes
    // 11,839 multiplications
}
```

---

## 6. Stage-by-Stage Progress

### Stage 1: Spartan Outer Sumcheck

| Metric | Value |
|--------|-------|
| Assertions | 2 |
| Constraints | 158,006 |
| Prove time | 460ms |
| Verify time | 1.3ms |

**What it verifies**: R1CS constraint satisfaction via univariate polynomial commitments.

**Files**: `jolt-core/src/zkvm/spartan/outer.rs`

### Stage 2: Product Virtualization, RAM RAF, Output Check

| Metric | Value |
|--------|-------|
| Assertions | 4 (cumulative) |
| Constraints | 532,186 |
| New constraints | +374,180 |

**Contains 5 batched sumchecks**:
- ProductVirtualRemainderVerifier
- RamRafEvaluationSumcheckVerifier
- RamReadWriteCheckingVerifier
- OutputSumcheckVerifier
- InstructionLookupsClaimReductionSumcheckVerifier

**Bug fixed**: `is_one()` spurious constraints (see Section 7.1)

### Stage 3: Shift, Instruction Input, Register Reduction

| Metric | Value |
|--------|-------|
| Assertions | 5 (cumulative) |
| Constraints | 763,394 |
| New constraints | +231,208 |

**Contains 3 batched sumchecks**:
- Spartan shift (next-cycle values)
- Instruction input (operand constraints)
- Register claim reduction

**Status**: Passed on first attempt after Stage 2 fix.

### Stage 4: Register R/W, RAM Val Evaluation, RAM Val Final

| Metric | Value |
|--------|-------|
| Assertions | 10 (cumulative) |
| Constraints | 1,048,560 |
| New constraints | +285,166 |

**Contains 4 batched sumchecks**:
- Register read/write checking
- RAM address booleanity
- RAM value evaluation
- RAM value final

**Bug fixed**: AST traversal memoization (see Section 7.3)

### Stage 5: Register Val Eval, RAM Hamming, RAM RA Reduction, Lookups

| Metric | Value |
|--------|-------|
| Assertions | 13 (cumulative) |
| Constraints | 1,531,516 |
| New constraints | +482,956 |

**Contains 4 batched sumchecks**:
- Register value evaluation
- RAM Hamming booleanity
- RAM address reduction
- Lookups read-after-final

**Bug fixed**: Iterative AST traversal for code generation (see Section 7.4)

### Stage 6+: Pending

Stage 6 (polynomial commitment scheme opening) is under discussion and not yet implemented.

---

## 7. Bugs Fixed and Lessons Learned

### 7.1 Spurious Constraints from `is_one()` (Stage 2)

**Problem**: 3 unexpected constraints appeared checking `eq_product * 10 = 1`, `eq_product * 55 = 1`.

**Root cause**: `One::is_one()` default implementation uses `*self == Self::one()`, which triggers `PartialEq::eq` in constraint mode.

**Fix**: Override `is_one()` to check node structure directly:

```rust
fn is_one(&self) -> bool {
    matches!(get_node(self.root), Node::Atom(Atom::Scalar(v)) if v == SCALAR_ONE)
}
```

**Lesson**: Any trait method using `==` internally can trigger spurious constraints.

### 7.2 Node Aliasing / CSE Bug (Stage 2)

**Problem**: Assertions `a3`, `a4`, `a5` shared the same CSE variable but required different values.

**Root cause**: Global CSE merged structurally identical EqPolynomial evaluations from different sumcheck verifiers.

**Fix**: Per-constraint CSE namespacing:

```rust
fn make_cse_name(&self) -> String {
    match self.constraint_idx {
        Some(idx) => format!("cse_{}_{}", idx, self.cse_counter),
        None => format!("cse_{}", self.cse_counter),
    }
}
```

**Lesson**: Structural equality doesn't imply semantic equality when expressions depend on different runtime values.

### 7.3 AST Traversal Memoization (Stage 4)

**Problem**: Transpiler hung for 6+ minutes at "Checking for Mul-by-Zero Pattern".

**Root cause**: `count_mul_by_zero` function traversed AST recursively without memoization. Shared nodes were visited exponentially.

**Fix**: Add memoization cache:

```rust
fn count_mul_by_zero(node_id: usize, cache: &mut HashMap<usize, usize>) -> usize {
    if let Some(&count) = cache.get(&node_id) {
        return count;
    }
    // ... compute count
    cache.insert(node_id, count);
    count
}
```

**Lesson**: Always memoize recursive AST traversals when nodes are shared.

### 7.4 Stack Overflow in Code Generation (Stage 5)

**Problem**: Stack overflow during "Generating Gnark Circuit" even with 128MB stack.

**Root cause**: `generate_expr` recursively traversed deep AST. Stage 5's larger polynomials created deeper trees.

**Fix**: Convert to iterative two-phase algorithm:
1. Build post-order traversal using explicit stack
2. Generate expressions bottom-up from HashMap

```rust
pub fn generate_expr(&mut self, root: usize) -> String {
    // Phase 1: Post-order traversal
    let mut stack = vec![(root, false)];
    let mut post_order = Vec::new();
    while let Some((id, processed)) = stack.pop() {
        if processed { post_order.push(id); continue; }
        stack.push((id, true));
        // Push children...
    }

    // Phase 2: Generate in order
    for id in post_order {
        let expr = /* generate from already-computed children */;
        self.generated.insert(id, expr);
    }
    self.generated[&root].clone()
}
```

**Lesson**: Deep recursion on large ASTs requires iterative algorithms.

### 7.5 MleOpeningAccumulator Transcript Append (Stage 1)

**Problem**: `a1` assertion failed with transcript state divergence.

**Root cause**: `MleOpeningAccumulator::append_*` methods didn't call `transcript.append_scalar(claim)`.

**Fix**: Match real accumulator behavior:

```rust
fn append_virtual<T: Transcript>(&mut self, transcript: &mut T, ..., claim: &MleAst, ...) {
    transcript.append_scalar(claim);  // CRITICAL
    // ...
}
```

**Lesson**: Symbolic implementations must replicate ALL side effects, including transcript updates.

---

## 8. Commands Reference

### Full Pipeline

```bash
# 1. Generate proof with Poseidon transcript
cd /Users/home/dev/parti/cryptography/zkVMs/WonderJolt/jolt
cargo run -p fibonacci --release --features transcript-poseidon -- --save 10

# 2. Transpile to Gnark circuit
cargo run -p gnark-transpiler --bin transpile_stages

# 3. Run Go tests
cd gnark-transpiler/go
go test -v -run TestStages16CircuitProveVerify
```

### Quick Tests

```bash
# Solver only (fast, ~0.4s)
go test -v -run TestStages16CircuitSolver

# Sanity checks
go test -v -run "TestCorruptedWitnessRejected|TestRandomFuzzing|TestAssertionCountMatchesTheory|TestCircuitNotTrivial"
```

### Debug

```bash
# Rust debug output
cargo run -p fibonacci --release --features debug-expected-output,transcript-poseidon -- 10

# Inspect generated circuit
wc -l gnark-transpiler/go/stages16_circuit.go  # ~10,000 lines for Stage 5
```

---

## 9. Files Modified Summary

### Jolt-Core (~25 files)

| File | Changes |
|------|---------|
| `jolt-core/src/poly/opening_proof.rs` | Extended `OpeningAccumulator` trait with write methods |
| `jolt-core/src/subprotocols/sumcheck.rs` | Added `A` generic parameter |
| `jolt-core/src/subprotocols/sumcheck_verifier.rs` | Added `A` generic parameter to trait |
| `jolt-core/src/subprotocols/univariate_skip.rs` | Updated trait bounds |
| `jolt-core/src/zkvm/spartan/*.rs` | Updated all verifiers with `A` generic |
| `jolt-core/src/zkvm/ram/*.rs` | Updated all verifiers with `A` generic |
| `jolt-core/src/zkvm/registers/*.rs` | Updated all verifiers with `A` generic |
| `jolt-core/src/zkvm/instruction_lookups/*.rs` | Updated all verifiers with `A` generic |
| `jolt-core/src/zkvm/bytecode/*.rs` | Updated all verifiers with `A` generic |
| `jolt-core/src/zkvm/transpilable_verifier.rs` | **NEW**: Main transpilation orchestrator |
| `jolt-core/src/transcripts/poseidon.rs` | **NEW**: Poseidon transcript |
| `jolt-core/src/transcripts/poseidon_fq_params.rs` | **NEW**: Fq parameters |

### ZkLean-Extractor

| File | Changes |
|------|---------|
| `zklean-extractor/src/mle_ast.rs` | Core symbolic field: `is_one()` fix, zero-identity optimizations, `is_constant()`, `try_evaluate_constant()`, `from_node_id()` |
| `zklean-extractor/src/lib.rs` | Re-exports |

### Gnark-Transpiler

| File | Changes |
|------|---------|
| `gnark-transpiler/src/bin/transpile_stages.rs` | Main entry point, memoization fix, per-constraint CSE |
| `gnark-transpiler/src/codegen.rs` | Iterative traversal, `constraint_idx`, constant detection |
| `gnark-transpiler/src/mle_opening_accumulator.rs` | `OpeningAccumulator` impl, transcript append fix |
| `gnark-transpiler/src/poseidon_transcript.rs` | `PoseidonAstTranscript` |

### Go/Gnark

| File | Changes |
|------|---------|
| `gnark-transpiler/go/stages16_circuit.go` | **GENERATED**: Circuit code |
| `gnark-transpiler/go/stages16_witness.json` | **GENERATED**: Witness values |
| `gnark-transpiler/go/stages16_circuit_test.go` | Tests + sanity checks |
| `gnark-transpiler/go/poseidon/poseidon.go` | Poseidon hash implementation |
| `gnark-transpiler/go/poseidon/truncate.go` | Challenge derivation hints |

### Documentation

| File | Purpose |
|------|---------|
| `docs/gnark-transpilation-complete-reference.md` | **This document** |
| `docs/gnark-stage3-context.md` | Stage 3 context |
| `docs/gnark-stage4-context.md` | Stage 4 context + memoization bug |
| `docs/gnark-stage5-context.md` | Stage 5 context + stack overflow bug |
| `docs/gnark-transpilation-debugging.md` | Debugging reference |
| `docs/29EneroUpdateAkoi.md` | Weekly update with full history |

---

## Appendix: Verification DAG

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
Stage 4 (Register r/w, RAM val evaluation, RAM val final)
    │ produces claims on ra(r,j), Inc(j)
    ▼
Stage 5 (Register val eval, RAM Hamming, RAM ra reduction, Lookups read-raf)  ← CURRENT
    │ produces claims on committed polynomials
    ▼
Stage 6 (Bytecode read-raf, RAM ra virtual, Inc reduction, etc.)  ← PENDING
    │
    ▼
Stages 7-8 (Dory PCS opening, pairing checks)  ← FUTURE (manual Go implementation)
```

---

*Document generated: 2026-01-30*
*Last verified: Stages 1-5 passing with 100% corruption rejection rate*
