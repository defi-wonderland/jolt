# Code Walkthrough: The Gnark Transpiler

This document walks through the transpiler code as if I'm explaining it to you line by line. I'll flag things that look questionable and explain what each piece does.

---

## Entry Point: [main.rs](gnark-transpiler/src/main.rs)

This is where we kick off transpilation. Let me walk through it:

[Lines 5-10](gnark-transpiler/src/main.rs#L5-L10):
```rust
use gnark_transpiler::{generate_circuit_from_bundle, PoseidonMleTranscript};
use jolt_core::transcripts::Transcript;
use jolt_core::zkvm::stage1_only_verifier::{
    verify_stage1_with_transcript, Stage1TranscriptVerificationData,
};
use zklean_extractor::mle_ast::{AstBundle, InputKind, MleAst};
```

We import our key components:
- `PoseidonMleTranscript` — our symbolic transcript that creates Poseidon nodes instead of computing hashes
- `verify_stage1_with_transcript` — the actual Jolt verifier we're tracing
- `MleAst` — the recording type

[Lines 12-19](gnark-transpiler/src/main.rs#L12-L19):
```rust
fn main() {
    // Parameters from real Fibonacci proof (trace_length=2048)
    let num_rounds: usize = 12;
    let num_uni_skip_coeffs: usize = 28;
    let coeffs_per_round: usize = 3;
```

**⚠️ Hardcoded parameters.** These are specific to a Fibonacci proof with `trace_length=2048`. For a production transpiler, these would need to come from actual proof data or be configurable.

### What is Stage1TranscriptVerificationData?

Before we continue, let's understand what we're building. `Stage1TranscriptVerificationData` is the **shape of a real proof**. In an actual Jolt verification:

1. **Prover** generates a proof containing polynomial coefficients
2. **Verifier** receives this proof data and checks it

The struct contains:
- `uni_skip_poly_coeffs` — coefficients of the "univariate skip" polynomial (an optimization)
- `sumcheck_round_polys` — for each sumcheck round, a degree-2 polynomial (3 coefficients)
- `num_rounds` — how many sumcheck rounds

**We don't have actual proof values.** We're not verifying a real proof — we're *transpiling the verifier*. So instead of filling this struct with real numbers, we fill it with **symbolic placeholders** (`Var(0)`, `Var(1)`, etc.).

When the verifier runs with these symbolic inputs, every operation builds an AST node. The final AST describes "what the verifier would compute, given any proof." That AST becomes the Gnark circuit.

[Lines 27-36](gnark-transpiler/src/main.rs#L27-L36):
```rust
    // Track variable indices for input descriptions
    let mut input_descriptions: Vec<(u16, String)> = Vec::new();

    // Create Stage1TranscriptVerificationData with MleAst variables
    let uni_skip_poly_coeffs: Vec<MleAst> = (0..num_uni_skip_coeffs)
        .map(|i| {
            let idx = i as u16;
            input_descriptions.push((idx, format!("uni_skip_coeff_{}", i)));
            MleAst::from_var(idx)
        })
        .collect();
```

Here we create **symbolic input variables**. Each `MleAst::from_var(idx)` creates a `Var(idx)` atom in the arena. These represent the proof data that will be provided at verification time.

In the generated Gnark circuit, `Var(0)` becomes `circuit.X_0`, `Var(1)` becomes `circuit.X_1`, etc.

[Lines 38-48](gnark-transpiler/src/main.rs#L38-L48):
```rust
    let sumcheck_round_polys: Vec<Vec<MleAst>> = (0..num_rounds)
        .map(|round| {
            (0..coeffs_per_round)
                .map(|coeff| {
                    let idx = (num_uni_skip_coeffs + round * coeffs_per_round + coeff) as u16;
                    input_descriptions.push((idx, format!("sumcheck_r{}_c{}", round, coeff)));
                    MleAst::from_var(idx)
                })
                .collect()
        })
        .collect();
```

More symbolic inputs — the sumcheck polynomial coefficients for each round. Again, these aren't real values. `Var(28)` means "whatever coefficient 0 of round 0 will be at verification time."

**The indexing scheme:** variables are numbered sequentially to form circuit inputs:
```
Var(0)..Var(27)  → uni_skip_poly_coeffs (28 values)
Var(28)..Var(63) → sumcheck_round_polys (12 rounds × 3 coeffs = 36 values)
```

In the generated Gnark circuit, these become `circuit.X_0`, `circuit.X_1`, ..., `circuit.X_63` — the public inputs that the actual proof data will be assigned to.

[Lines 52-56](gnark-transpiler/src/main.rs#L52-L56):
```rust
    let data = Stage1TranscriptVerificationData {
        uni_skip_poly_coeffs,
        sumcheck_round_polys,
        num_rounds,
    };
```

Pack everything into the verification data struct that Jolt expects.

[Lines 60-61](gnark-transpiler/src/main.rs#L60-L61):
```rust
    // Create Poseidon transcript for symbolic execution
    let mut transcript: PoseidonMleTranscript = Transcript::new(b"jolt");
```

Create the symbolic transcript. The `Transcript::new(b"jolt")` call triggers (see [poseidon.rs:106-118](gnark-transpiler/src/poseidon.rs#L106-L118)):
```rust
// Inside PoseidonMleTranscript::new():
let label_field = Self::label_to_field(b"jolt");  // Convert "jolt" to field element
let initial_state = MleAst::poseidon(&label_field, &MleAst::from_i128(0), &MleAst::from_i128(0));
```

So the transcript starts with state = `Poseidon("jolt", 0, 0)` — already a symbolic expression.

[Lines 64-65](gnark-transpiler/src/main.rs#L64-L65):
```rust
    // Run verification with MleAst and Poseidon transcript
    let result = verify_stage1_with_transcript(data, &mut transcript);
```

**This is where the magic happens.** We call the actual Jolt verifier, but it's operating on `MleAst` values. Every arithmetic operation builds the AST. Every transcript call creates Poseidon nodes.

The result contains:
- `power_sum_check`: MleAst that should equal zero
- `sumcheck_consistency_checks`: Vec of MleAsts that should each equal zero
- `final_claim`: MleAst representing the output

**Why must these equal zero?** This comes from the sumcheck protocol:

1. **`power_sum_check`**: In the first round, the prover sends polynomial coefficients. The verifier computes `Σ coeff[j] * S_j` where `S_j` are precomputed "power sums" over the evaluation domain. For a valid proof, this sum must be zero — it's checking that the polynomial has the right structure.

2. **`sumcheck_consistency_checks`**: In each sumcheck round, the prover sends a polynomial `g(x)`. The verifier checks that `g(0) + g(1) = previous_claim`. The constraint is expressed as `g(0) + g(1) - claim = 0`. A cheating prover can't satisfy this unless they actually know the correct polynomial.

These "should be zero" constraints become `api.AssertIsEqual(expr, 0)` in the Gnark circuit.

[Lines 68-72](gnark-transpiler/src/main.rs#L68-L72):
```rust
    // Build AstBundle from the result
    let mut bundle = AstBundle::new();
    bundle.snapshot_arena();
```

`snapshot_arena()` copies the current global arena into the bundle (see [mle_ast.rs:1275-1279](zklean-extractor/src/mle_ast.rs#L1275-L1279)). This captures all the nodes we built during verification.

[Lines 74-77](gnark-transpiler/src/main.rs#L74-L77):
```rust
    // Add input variable descriptions (all are ProofData for Stage 1)
    for (idx, name) in &input_descriptions {
        bundle.add_input(*idx, name.clone(), InputKind::ProofData);
    }
```

Record metadata about what each variable represents. This helps generate meaningful names in the circuit.

[Lines 79-86](gnark-transpiler/src/main.rs#L79-L86):
```rust
    // Add constraints with their assertion types
    bundle.add_constraint_eq_zero("power_sum_check", result.power_sum_check.root());

    for (i, check) in result.sumcheck_consistency_checks.iter().enumerate() {
        bundle.add_constraint_eq_zero(format!("sumcheck_consistency_{}", i), check.root());
    }

    bundle.add_constraint_eq_public("final_claim", result.final_claim.root(), "expected_final_claim");
```

Add the constraints:
- `power_sum_check == 0`
- `sumcheck_consistency_i == 0` for each round
- `final_claim == expected_final_claim` (public input)

[Lines 93-94](gnark-transpiler/src/main.rs#L93-L94):
```rust
    // Generate Gnark circuit from AstBundle
    let circuit = generate_circuit_from_bundle(&bundle, "Stage1Circuit");
```

Walk the AST and emit Gnark code (see [codegen.rs:274-395](gnark-transpiler/src/codegen.rs#L274-L395)). We'll look at this function next.

---

## The Recording Type: [mle_ast.rs](zklean-extractor/src/mle_ast.rs)

This is the core data structure. Let me walk through the key parts:

### Thread-Local Storage for Transcript Integration

[Lines 30-32](zklean-extractor/src/mle_ast.rs#L30-L32) and [Lines 47-49](zklean-extractor/src/mle_ast.rs#L47-L49):
```rust
thread_local! {
    static PENDING_CHALLENGE: RefCell<Option<MleAst>> = RefCell::new(None);
}

thread_local! {
    static PENDING_APPEND: RefCell<Option<MleAst>> = RefCell::new(None);
}
```

These are the global variables we use to smuggle MleAst through the transcript interface. Two separate channels:
- `PENDING_APPEND`: for `append_scalar` (sending data to transcript)
- `PENDING_CHALLENGE`: for `challenge_scalar` (receiving data from transcript)

**⚠️ Why two separate variables?** Looking at the code, they're used in different directions of data flow. But they could potentially interfere if a challenge is requested before the previous one is consumed. The code assumes strict alternation.

### The Node Types

[Lines 105-113](zklean-extractor/src/mle_ast.rs#L105-L113):
```rust
pub enum Atom {
    /// A constant value.
    Scalar(Scalar),
    /// A variable, represented by an index into a register of variables
    Var(Index),
    /// A let-bound variable, used for common sub-expression elimination
    NamedVar(LetBinderIndex),
}
```

Three kinds of leaves:
- `Scalar(42)` — a constant
- `Var(3)` — an input variable (becomes `circuit.X_3`)
- `NamedVar(7)` — a CSE reference (becomes `cse_7`)

[Lines 130-136](zklean-extractor/src/mle_ast.rs#L130-L136):
```rust
pub enum Edge {
    /// An atomic (var or const) AST element.
    Atom(Atom),
    /// A reference to a node in the arena.
    NodeRef(NodeId),
}
```

An edge is either a leaf (atom) or a reference to an interior node. This avoids having `NodeRef` wrap atoms unnecessarily.

[Lines 139-162](zklean-extractor/src/mle_ast.rs#L139-L162):
```rust
pub enum Node {
    Atom(Atom),
    Neg(Edge),
    Inv(Edge),
    Add(Edge, Edge),
    Mul(Edge, Edge),
    Sub(Edge, Edge),
    Div(Edge, Edge),
    Poseidon(Edge, Edge, Edge),
    Keccak256(Edge),
}
```

The full set of operations. Note:
- `Poseidon` takes 3 arguments: (state, round, data)
- All binary ops store their children as `Edge`, allowing direct embedding of atoms

### The Arena

[Lines 73-87](zklean-extractor/src/mle_ast.rs#L73-L87):
```rust
type NodeId = usize;

static NODE_ARENA: OnceLock<RwLock<Vec<Node>>> = OnceLock::new();

fn node_arena() -> &'static RwLock<Vec<Node>> {
    NODE_ARENA.get_or_init(|| RwLock::new(Vec::new()))
}

pub fn insert_node(node: Node) -> NodeId {
    let arena = node_arena();
    let mut guard = arena.write().expect("node arena poisoned");
    let id = guard.len();
    guard.push(node);
    id
}
```

A global, growable array. `insert_node` appends and returns the index.

**⚠️ Potential issue:** The arena never shrinks. If you run multiple transpilations in the same process, nodes accumulate. This could be a memory leak for long-running processes. For a CLI tool that runs once and exits, it's fine.

### The MleAst Struct

[Lines 167-175](zklean-extractor/src/mle_ast.rs#L167-L175):
```rust
pub struct MleAst {
    root: NodeId,
    reg_name: Option<char>,
}
```

Just an index and an optional register name (used for formatting). As we discussed — it's just a number.

### Arithmetic Implementations

[Lines 737-744](zklean-extractor/src/mle_ast.rs#L737-L744):
```rust
impl std::ops::Add<&Self> for MleAst {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self.binop(Node::Add, rhs);
        self
    }
}
```

When you add two MleAst values, it calls `binop`:

[Lines 209-215](zklean-extractor/src/mle_ast.rs#L209-L215):
```rust
fn binop(&mut self, constructor: impl FnOnce(Edge, Edge) -> Node, rhs: &Self) {
    self.merge_reg_name(rhs.reg_name);
    let lhs_edge = edge_for_root(self.root);
    let rhs_edge = edge_for_root(rhs.root);
    self.root = insert_node(constructor(lhs_edge, rhs_edge));
}
```

This:
1. Converts both roots to edges
2. Creates a new node with the constructor (e.g., `Node::Add`)
3. Inserts it into the arena
4. Updates `self.root` to point to the new node

The result is that `a + b` doesn't compute anything — it builds `Add(edge_a, edge_b)` in the arena.

### The Serialization Hack

[Lines 1107-1123](zklean-extractor/src/mle_ast.rs#L1107-L1123):
```rust
impl CanonicalSerialize for MleAst {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        // Store self in thread-local so PoseidonMleTranscript::append_scalar can retrieve it.
        set_pending_append(self.clone());
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        // Return 32 bytes (standard field element size) so append_scalar works
        32
    }
}
```

When the transcript calls `serialize`, we stash the MleAst in `PENDING_APPEND` and return success. The bytes written are... nothing, actually. We don't write anything to the writer.

**⚠️ Observation:** `serialized_size` returns 32, but `serialize_with_mode` writes 0 bytes. This mismatch could cause issues if any code actually relies on the serialized data. For the transcript use case, it works because the transcript ignores the bytes anyway.

### The Deserialization Hack

[Lines 969-976](zklean-extractor/src/mle_ast.rs#L969-L976):
```rust
fn from_bytes(_bytes: &[u8]) -> Self {
    // Check if there's a pending challenge from PoseidonMleTranscript
    if let Some(challenge) = take_pending_challenge() {
        return challenge;
    }
    // Fallback: create constant from bytes (for non-transpilation use)
    MleAst::from_i128(0)
}
```

When the transcript returns a challenge, it calls `from_bytes`. We ignore the bytes and return whatever's in `PENDING_CHALLENGE`.

---

## The Symbolic Transcript: [poseidon.rs](gnark-transpiler/src/poseidon.rs)

### The Big Picture

In a real verification, the transcript is a Fiat-Shamir construction: it hashes together all the data exchanged so far to produce "random" challenges. The verifier and prover both maintain the same transcript state, so they derive the same challenges.

For transpilation, we don't want to compute actual hashes. We want to **record** that hashing happens, so the generated circuit will do the hashing. The `PoseidonMleTranscript` is a "fake" transcript that:

1. **Doesn't hash anything** — it builds AST nodes instead
2. **Tracks the dependency chain** — each Poseidon node points to the previous state
3. **Produces symbolic challenges** — returns MleAst values that represent "whatever this hash would produce"

### The Structure

[Lines 24-29](gnark-transpiler/src/poseidon.rs#L24-L29):
```rust
pub struct PoseidonMleTranscript {
    state: MleAst,      // Symbolic — points to a Poseidon node in the arena
    n_rounds: u32,      // Concrete — we know exactly how many rounds happen
}
```

The state is symbolic because it depends on the (unknown) proof data. The round counter is concrete because the verifier's control flow is deterministic — we know exactly how many challenges get derived.

### How State Evolves

When the transcript is created with label "jolt", the initial state becomes:
```
state = Poseidon("jolt", 0, 0)   // A node in the arena
```

When the verifier appends proof data `x` to the transcript:
```
state = Poseidon(old_state, round, x)   // A NEW node, pointing to the old one
```

When the verifier requests a challenge:
```
challenge = Poseidon(state, round, 0)   // Another new node
state = challenge                        // State advances
```

Each operation creates a new Poseidon node. The nodes form a chain — each one references the previous state. This chain captures the exact sequence of transcript operations.

### Appending Data: The Smuggling Dance

The verifier calls `transcript.append_scalar(&x)` where `x` is an MleAst. But the `Transcript` trait expects to serialize `x` into bytes. We can't meaningfully serialize a symbolic expression.

The solution: **smuggle the MleAst through a global variable**.

[Lines 132-144](gnark-transpiler/src/poseidon.rs#L132-L144) — when `append_scalar` is called:
1. It calls `x.serialize()` — which triggers `MleAst::serialize_with_mode`
2. That function **ignores the writer** and stashes `x` in `PENDING_APPEND`
3. Back in `append_scalar`, we call `take_pending_append()` to retrieve `x`
4. We create `Poseidon(state, round, x)` — a node that references the actual MleAst

The bytes are theater. The real data travels through the global variable.

### Deriving Challenges: Smuggling in Reverse

The verifier calls `transcript.challenge_scalar()` expecting a field element. We need to return an MleAst representing "whatever this hash would produce."

[Lines 175-179](gnark-transpiler/src/poseidon.rs#L175-L179) and [Lines 86-93](gnark-transpiler/src/poseidon.rs#L86-L93):
1. Create a `Poseidon(state, round, 0)` node — this represents the challenge
2. Stash it in `PENDING_CHALLENGE`
3. Return `F::from_bytes(&[0u8; 32])` — the trait requires returning bytes
4. Inside `MleAst::from_bytes`, we **ignore the bytes** and return from `PENDING_CHALLENGE`

The verifier receives an MleAst that represents "the challenge." When it later computes `challenge * something`, that creates a `Mul` node whose child is the Poseidon node. The dependency is captured.

### Why the Round Counter Matters

The `n_rounds` counter provides **domain separation**. Each Poseidon call gets a different round number:
```
Poseidon(state, 0, data1)
Poseidon(state, 1, data2)
Poseidon(state, 2, 0)      // challenge derivation
```

This ensures that even if the same data is hashed at different points, the results differ. It's a standard technique to prevent certain attacks on Fiat-Shamir transcripts.

### Code Details

**Label conversion** ([Lines 48-59](gnark-transpiler/src/poseidon.rs#L48-L59)): The string "jolt" becomes the integer 1953198954 (little-endian). This is a constant baked into the circuit.

**⚠️ Potential issue:** The assertion allows 32-byte labels but i128 can only hold 16 bytes without overflow.

**Challenge powers** ([Lines 197-211](gnark-transpiler/src/poseidon.rs#L197-L211)): When the verifier needs `[1, r, r², r³, ...]`, we derive one challenge `r` and build a chain of multiplications. Each power becomes a `Mul` node referencing the previous one.

---

## Code Generation: [codegen.rs](gnark-transpiler/src/codegen.rs)

### The Big Picture

At this point we have an AST — a directed acyclic graph of nodes representing the verifier's computation. Now we need to **translate it to Gnark code**.

The translation is mostly mechanical:
- `Add(a, b)` → `api.Add(a, b)`
- `Mul(a, b)` → `api.Mul(a, b)`
- `Poseidon(s, r, d)` → `poseidon.Hash(api, s, r, d)`
- `Var(3)` → `circuit.X_3`
- `Scalar(42)` → `42`

But there's one complication: **shared subexpressions**.

### The Sharing Problem

Consider this AST:
```
      constraint_1          constraint_2
           |                     |
          Add                   Mul
         /   \                 /   \
        A     B               A     C
```

Node `A` is referenced by both constraints. If we naively generate code, we'd compute `A` twice:
```go
constraint1 := api.Add(compute_A(), compute_B())
constraint2 := api.Mul(compute_A(), compute_C())  // redundant!
```

In a circuit, redundant computation means redundant constraints — which bloats the proof and slows verification.

### Common Subexpression Elimination (CSE)

The solution: **detect shared nodes and compute them once**.

```go
cse_0 := compute_A()                              // computed once
constraint1 := api.Add(cse_0, compute_B())        // reuse
constraint2 := api.Mul(cse_0, compute_C())        // reuse
```

This is called Common Subexpression Elimination (CSE). The codegen does it automatically.

### Two-Pass Algorithm

The implementation uses two passes over the AST:

**Pass 1: Count references**
Walk the graph and count how many times each node is referenced. If a node has refcount > 1, it's shared.

**Pass 2: Generate code**
Walk again and emit code. When visiting a shared node:
- First visit: generate code, assign to a CSE variable (`cse_0`, `cse_1`, ...), remember the mapping
- Subsequent visits: just return the variable name

This ensures shared computations happen exactly once.

### Why This Matters for Poseidon

The transcript creates a **chain** of Poseidon nodes:
```
Poseidon("jolt", 0, 0)
    └─► Poseidon(prev, 1, data1)
            └─► Poseidon(prev, 2, data2)
                    └─► Poseidon(prev, 3, 0)   ← challenge
```

Each node references the previous one. Without CSE, generating code for the challenge would recursively expand the entire chain — and if multiple constraints reference the same challenge, the chain would be duplicated.

With CSE, each Poseidon in the chain becomes a `cse_N` variable, computed once, referenced many times.

### The Translation Rules

[Lines 95-104](gnark-transpiler/src/codegen.rs#L95-L104) — Atoms (leaves):
- `Scalar(42)` → `42` (literal integer in Go)
- `Var(3)` → `circuit.X_3` (circuit input field)
- `NamedVar(7)` → `cse_7` (CSE variable reference)

[Lines 107-174](gnark-transpiler/src/codegen.rs#L107-L174) — Operations:
- `Add(a, b)` → `api.Add(a_code, b_code)`
- `Mul(a, b)` → `api.Mul(a_code, b_code)`
- `Poseidon(s, r, d)` → `poseidon.Hash(api, s_code, r_code, d_code)`

The Gnark `api` provides field arithmetic. The generated code builds an arithmetic circuit.

### The Generated Circuit Structure

[Lines 274-395](gnark-transpiler/src/codegen.rs#L274-L395) — The output is a complete Go file:

```go
package jolt_verifier

import (
    "github.com/consensys/gnark/frontend"
    "github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

type Stage1Circuit struct {
    X_0 frontend.Variable `gnark:",public"`
    X_1 frontend.Variable `gnark:",public"`
    // ... one field per proof input
    ExpectedFinalClaim frontend.Variable `gnark:",public"`
}

func (circuit *Stage1Circuit) Define(api frontend.API) error {
    // CSE bindings (shared subexpressions)
    cse_0 := poseidon.Hash(api, 1953198954, 0, 0)
    cse_1 := poseidon.Hash(api, cse_0, 1, circuit.X_0)
    // ...

    // Constraints
    powerSumCheck := api.Add(...)
    api.AssertIsEqual(powerSumCheck, 0)

    // ... more constraints ...

    return nil
}
```

The circuit struct declares inputs. The `Define()` method contains the computation. Gnark compiles this into R1CS constraints for Groth16.

### What About Large Numbers?

**⚠️ Potential issue:** Scalars are emitted as plain integers (`42`). Go's `int` is 64-bit, but our `Scalar` type is `i128`. Very large constants could overflow. For the verifier's constants (small integers like round numbers), this is fine. For field elements near the modulus, it could be problematic.

---

## Critical Observations

### Things That Look Correct

1. **The smuggling mechanism** works as intended — thread-local storage passes MleAst through the serialize/deserialize boundary.

2. **The AST structure** is sound — arena allocation, copy semantics, proper DAG representation.

3. **Reference-count-based CSE** is a good approach — it correctly identifies shared subexpressions.

### Things That Look Questionable

1. **label_to_field overflow:** Allows 32-byte labels but uses i128 (16 bytes max without overflow).

2. **Hardcoded parameters in main.rs:** The circuit is generated for specific proof dimensions.

3. **Scalar representation in Gnark:** Large i128 values might not serialize correctly to Go.

4. **Global arena never cleared:** Could accumulate garbage across multiple runs.

5. **serialized_size mismatch:** Returns 32 but writes 0 bytes.

### Things I'm Uncertain About

1. **Poseidon parameter compatibility:** The code uses `vocdoni/gnark-crypto-primitives/poseidon`. Does this use the same MDS matrix and round constants as Jolt's `light-poseidon`? This is critical for correctness.

2. **Transcript state initialization:** The initial state is `Poseidon("jolt", 0, 0)`. Is this exactly what Jolt's real transcript does?

3. **Domain separation:** The `n_rounds` counter is used for domain separation. Is this sufficient? Does Jolt's transcript handle domain separation differently?

---

## Questions for You

1. Have the Poseidon parameters been verified to match between Rust and Gnark implementations?

2. Is the `stage1_only_verifier` the complete verification or just part of it? The name suggests it's stage 1 of a multi-stage process.

3. What's the plan for handling variable-length proofs (different trace lengths)?
