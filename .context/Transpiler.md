# The Transpiler: Watching Code Think

## Two Ways to Understand a Machine

Imagine you're given a mechanical calculator from the 1940s — gears, levers, rotating drums. You need to build an identical one, but in a completely different medium: say, hydraulics. How do you proceed?

One approach is to disassemble the original. Take it apart, catalog every gear, measure every cam angle, understand how each component transforms motion. Then figure out the hydraulic equivalents: this gear ratio becomes that valve opening, this lever becomes that piston. You're analyzing the *structure* of the machine.

The other approach is to treat it as a black box. Feed it inputs, observe the outputs. Press these buttons, watch those drums spin. You don't care *how* it computes — you care *what* it computes. Once you've traced the input-output behavior, you can build any mechanism that produces the same behavior.

The first approach is **static analysis**. The second is **dynamic tracing**. For translating Jolt's Rust verifier into Gnark circuits, static analysis would require understanding every gear in Rust's machinery — a multi-year effort. So we do something cleverer: we watch the code think.

---

## The Linguistics of Programming Languages

Natural languages have a useful distinction between **syntax** and **semantics**. Syntax is the structure of a sentence — which words go where, how clauses nest. Semantics is what the sentence *means*. "The cat sat on the mat" and "Le chat s'est assis sur le tapis" have completely different syntax but (roughly) the same semantics.

Programming languages have the same split. The *syntax* of `x * y + z` is a tree: multiplication of `x` and `y`, then addition with `z`. The *semantics* is what happens when you run it: numbers get multiplied and added, and you get a result.

Here's the key insight: **you can change the semantics without changing the syntax**.

In linguistics, this is like metaphor. "Time is money" uses the syntax of identity (`A is B`) but the semantics of analogy. The sentence executes differently in your mind than a literal identity like "water is H₂O."

In programming, this is **operator overloading**. The expression `x * y` looks the same whether `x` and `y` are integers, matrices, or polynomials. But the *meaning* of `*` — what actually happens when you run it — depends on the types involved. Multiply two integers, you get arithmetic. Multiply two matrices, you get linear algebra. Multiply two polynomials, you get convolution.

The transpiler exploits this ruthlessly. We define a type where `*` doesn't multiply — it *records* that a multiplication should happen. The code runs, but instead of computing a result, it builds a description of the computation.

---

## The Physicist's Approach: Scattering Experiments

There's an analogy in physics that might resonate. When physicists want to understand the internal structure of a proton, they don't try to open it up and look inside. They can't. Instead, they throw things at it — electrons, photons, other protons — and watch what comes out. The scattering patterns reveal the internal structure indirectly.

This is exactly what the transpiler does. We can't easily "open up" Rust code and understand its structure directly (the generics, traits, and macros make this intractable). But we *can* throw symbolic inputs at it and observe what comes out.

The "symbolic inputs" are variables that haven't been assigned values yet — placeholders like *x*, *y*, *z* in algebra. When you compute `x + y` with actual numbers, you get a number. When you compute `x + y` with symbols, you get the expression `x + y`. The expression *is* the result.

Run the verifier with symbolic inputs, and the output is a symbolic expression — a complete description of how the verifier transforms its inputs into outputs. We've probed the structure by observing the behavior.

---

## What Static Analysis Would Require

Before diving into the dynamic approach, it's worth understanding why the static approach fails. "Just parse the Rust and translate it" sounds reasonable until you encounter what Rust actually looks like.

**Generics** are the first wall. When you write:

```rust
fn verify<F: JoltField>(x: F, y: F) -> F {
    x * y + x
}
```

The function doesn't say what `F` is. It's a placeholder — like saying "for any type that knows how to do field arithmetic." The expression `x * y` could mean integer multiplication, floating-point multiplication, polynomial multiplication, or matrix multiplication. You don't know until someone actually calls `verify` with a specific type.

A static analyzer would need to find every place `verify` gets called, figure out what type `F` becomes in each case, and only then understand what `x * y` means. In a large codebase with libraries calling libraries, this becomes a graph traversal problem across thousands of files.

**Traits** compound this. That `: JoltField` part says "`F` must implement the `JoltField` interface." But `JoltField` extends other traits — `Add`, `Mul`, `Sub`, `Div`, `One`, `Zero`. Each of those might be implemented in a different file. To know what `x * y` does, you chase a chain of trait implementations that might span multiple crates.

**Macros** are the final blow. Rust's macro system generates code at compile time. A single line like `impl_field_ops!(MyType)` might expand into hundreds of lines of trait implementations. You can't understand the code without expanding the macros — which requires running a significant portion of the Rust compiler.

Static analysis of real Rust isn't impossible, but it's a multi-year project requiring deep compiler expertise. The transpiler sidesteps all of this.

---

## The Recording Type: Algebra as Data Structure

The transpiler's central trick is a type called `MleAst` that *looks* like a number but *acts* like a tape recorder.

In normal arithmetic, when you compute `3 + 5`, you get `8`. The operation happens, the result appears, the process is forgotten.

With `MleAst`, when you compute `a + b`, you get a data structure that says "add *a* and *b*." Nothing is computed. The operation is recorded for later.

Think of it like building a recipe instead of cooking a meal. Normal execution: "combine flour and water, knead, let rise, bake → bread." Recording execution: "Step 1: combine flour and water. Step 2: knead. Step 3: let rise. Step 4: bake." The recipe is a *description* of the process, not the process itself.

The data structure that emerges is a **directed acyclic graph** (DAG). Each node is either:

- An **atom**: a constant value (like `3`) or a variable (like `x_0`) — these are leaves, with no children
- An **operation**: addition, multiplication, negation, inversion, or hashing — these have children

Operations vary in how many inputs they take. Unary operations (negation, inversion) have one child. Binary operations (add, multiply, subtract, divide) have two. Poseidon hashing takes three inputs (state, round counter, data), so it has three children. The structure isn't a binary tree — it's a heterogeneous graph where each node type has a fixed arity.

For example, the expression `(a + b) * a` becomes:

```
      Mul
     /   \
   Add    a
   / \
  a   b
```

The root is a multiplication. Its left child is an addition, whose children are the atoms `a` and `b`. Its right child is the atom `a` again.

Why a DAG rather than a tree? Because subexpressions can be **shared**. Consider `(a + b) * (a + b)`. In a pure tree, you'd duplicate the `Add` node. In a DAG, both branches of the multiplication point to the *same* `Add` node:

```
       Mul
      /   \
     Add ←─┘   (same node, two parents)
     / \
    a   b
```

This sharing is what makes common subexpression elimination (CSE) possible. When the codegen encounters a node with multiple parents, it computes it once and stores the result in a variable, rather than recomputing it at each use site.

This structure — the **abstract syntax tree** (AST) — is what compilers build when they parse source code. But we didn't parse anything. We ran the code and watched the graph grow.

---

## The Arena: Where Nodes Live

Trees are awkward to work with directly in Rust. The natural representation — nodes containing pointers to child nodes — runs into ownership issues. If a node "owns" its children, you can't share children between nodes. If nodes share children, you need reference counting, which has its own complications.

The transpiler uses a simpler structure: a **flat arena**. All nodes live in a single growable array:

```rust
static NODE_ARENA: OnceLock<RwLock<Vec<Node>>> = OnceLock::new();
```

Think of it as a library where every book gets a numbered shelf position. When a new node is created, it gets pushed to the end of the array and assigned the next available index. A node like `Add(3, 7)` means "addition of the nodes at index 3 and index 7." Children are referenced by their position, not by pointers.

When you execute `a + b`:

1. Look up the nodes for `a` and `b` in the arena
2. Create a new `Add` node referencing their indices
3. Push it to the arena
4. Return the new index

The tree grows node by node. By the end of execution, the arena contains the entire computation graph.

---

## What MleAst Actually Is: Just a Number

Here's something that might surprise you: `MleAst` is almost nothing. Literally.

```rust
pub struct MleAst {
    root: usize,  // That's it. Just a number like 7, 42, 183...
}
```

That's the entire structure. An `MleAst` is just an **index** — a position in the arena array. When you have an `MleAst` with `root: 42`, it means "the expression I represent is whatever node sits at position 42 in the arena."

It's like a library call number. When you check out a book, you don't carry the library around. You get a reference that says "shelf 3, row 7, position 12." The call number *is not* the book — it's directions to where the book lives.

`MleAst` is a call number. When you write `let result = a + b`, you're not stuffing a tree into `result`. You're creating an `Add` node in the arena (say, at position 42), and `result` is just the number `42`.

Here's a concrete example. Suppose we compute `(a + b) * c`:

```
Step 1: Create atom for variable 'a' → stored at ARENA[0]
Step 2: Create atom for variable 'b' → stored at ARENA[1]
Step 3: Create atom for variable 'c' → stored at ARENA[2]
Step 4: Compute a + b → creates Add(0, 1), stored at ARENA[3]
Step 5: Compute (a + b) * c → creates Mul(3, 2), stored at ARENA[4]
```

The result of the final computation is `MleAst { root: 4 }`. That's it — just the number 4. But that number tells you: "to find the expression, look at position 4 in the arena."

Position 4 contains `Mul(3, 2)`. Position 3 contains `Add(0, 1)`. Positions 0, 1, 2 contain the original variables. Follow the indices, and you can reconstruct the whole tree.

This design has practical consequences:
- **Copying is free.** Copying a 64-bit integer is trivial.
- **Comparison is cheap.** Same index = same expression.
- **Sharing is automatic.** Multiple `MleAst` values can point to the same node.

When the verifier passes around `MleAst` values, it's passing around small integers, not complex data structures. The arena holds all the complexity.

---

## The Boundary Problem: When Interfaces Don't Fit

Here's where things get interesting. The Jolt verifier doesn't just do arithmetic — it uses **hash functions** to derive random challenges. This is the Fiat-Shamir transform: turn an interactive protocol into a non-interactive one by replacing the verifier's random choices with hash outputs.

Jolt's transcript interface looks like this:

```rust
trait Transcript {
    fn append_scalar<F: JoltField>(&mut self, scalar: &F);
    fn challenge_scalar<F: JoltField>(&mut self) -> F;
}
```

You append values to a running hash state, then squeeze out challenges. Simple enough. But the interface expects `F` to be a *number* — something that can be serialized to bytes and deserialized back.

`MleAst` doesn't represent a concrete value — it represents an expression. What bytes should encode "the sum of variables *a* and *b*"? There's no sensible answer.

This is a **boundary problem**. The interface was designed with one semantics in mind (actual field arithmetic), and we're trying to slip through it with a completely different semantics (symbolic recording). The types technically match — `MleAst` implements `JoltField` — but the operations don't make sense.

---

## The Smuggling Problem

To understand the solution, we need to understand why there's a problem at all.

**Serialization** is the process of converting a data structure into a sequence of bytes — a flat stream that can be written to disk, sent over a network, or fed to a hash function. The number `42` might serialize to the bytes `[0x2A, 0x00, 0x00, 0x00]`. A more complex structure like a point on an elliptic curve becomes a longer byte sequence.

The transcript interface assumes it's working with numbers. When you call `append_scalar(&x)`, the interface internally calls `x.serialize()` to get bytes, then feeds those bytes to the hash function. This works perfectly when `x` is an actual field element.

But `MleAst` doesn't represent a concrete value — it represents a symbolic expression. There's no sensible way to "serialize" the expression `a + b * c` into bytes that a hash function could meaningfully consume. The whole point is that `a`, `b`, and `c` are *unknown variables*, not concrete values.

We need to smuggle the `MleAst` through an interface that expects bytes.

---

## The Solution: A Global Variable as Side Channel

The trick is simple: use a **global variable** as a side channel. Both the sender (`MleAst::serialize`) and the receiver (`Transcript::append_scalar`) know about this shared storage location.

```rust
// A global variable that can hold one MleAst
thread_local! {
    static PENDING: RefCell<Option<MleAst>> = RefCell::new(None);
}
```

The flow:
1. `MleAst::serialize()` stashes `self` in `PENDING`, returns dummy bytes
2. `Transcript::append_scalar()` receives the dummy bytes, ignores them
3. `Transcript::append_scalar()` reads from `PENDING`, gets the actual `MleAst`
4. Creates a Poseidon node using that `MleAst`

The bytes are theater. The real data moves through the global variable.

---

## Critical Point: No Actual Hashing Happens

Before going further, let's be very clear about something that's easy to miss:

**The symbolic transcript doesn't compute any hashes.** It just *records* that a hash should happen.

Remember: the entire transpiler is about recording operations, not executing them. Just like `MleAst`'s `+` operator doesn't add numbers — it creates an `Add` node — the symbolic transcript's "hash" operation doesn't hash anything. It creates a `Poseidon` node.

When the real transcript processes data:
```
Input: x = 42
State: 0x1234...
Output: Poseidon(0x1234..., round, 42) = 0x5678...  ← actual computation
```

When the symbolic transcript processes data:
```
Input: x = MleAst representing (a + b)
State: MleAst node #7
Output: new MleAst node #8 = Poseidon(node #7, round, (a + b))  ← just a label!
```

The `Poseidon` node doesn't contain a hash value. It contains *references to its inputs*: "I am the result of hashing these three things." The actual hashing happens much later, when the generated Gnark circuit runs with real numbers.

---

## The Handoff in Detail

Here's the key constraint: **we don't modify Jolt's verifier code**. The verifier is written to call `transcript.append_scalar(&x)` — that's baked in. We can't remove that call or skip it. What we *can* control is:

1. The `MleAst` type (our recording type that implements `JoltField`)
2. The symbolic transcript (our implementation of the `Transcript` trait)

When the verifier runs, it *will* call `append_scalar`. Our job is to make that call do something useful — create a Poseidon node — instead of crashing when it tries to serialize an expression into bytes.

Here's the sequence when the verifier calls `transcript.append_scalar(&x)`:

**What the interface thinks is happening:**
1. Transcript says: "Give me `x` as bytes"
2. `x` converts itself to bytes
3. Transcript feeds the bytes to the Poseidon hash function
4. Poseidon updates its internal state

**What actually happens (with our trick):**

```
transcript.append_scalar(&x)     ← verifier calls this
         │
         │  // Inside append_scalar:
         │
         ▼
    x.serialize()                ← transcript asks for bytes
         │
         │  // Inside MleAst's serialize:
         │  PENDING.set(Some(self))  ← stash the MleAst in the global variable
         │  return [0x00, 0x00, ...] ← return garbage bytes
         │
         ▼
    // Back in append_scalar:
    // bytes = [0x00, 0x00, ...]  ← received garbage (ignored)
    let x = PENDING.take()        ← read from the SAME global variable
    // x is now the MleAst!
    //
    self.state = Poseidon(self.state, round, x)  ← build AST node
```

Both `MleAst::serialize()` and `Transcript::append_scalar()` know about the same global variable `PENDING`. One writes, the other reads. The bytes are ignored entirely.

No bytes are hashed. No actual Poseidon computation occurs. But we did create a Poseidon *node* in the arena. That's the whole point.

Later, when the verifier computes `challenge * something`, it creates:

```
         Mul
        /   \
   Poseidon  (something)
   /  |  \
state round (a+b)
```

The Poseidon node is now a dependency in the graph. When codegen walks this tree, it emits:

```go
cse_43 := poseidon.Hash(api, state, round, input_42)
result := api.Mul(cse_43, something)
```

The hash *will* be computed — just not now, during tracing. It happens later, when the Gnark circuit runs with real values.

---

## The Return Trip

Getting challenges *out* of the transcript works the same way.

When the verifier calls `transcript.challenge_scalar()`, it expects a field element — a number derived from hashing. We want to return an `MleAst` representing "whatever the hash output would be."

**What the interface thinks is happening:**
1. Transcript computes Poseidon hash, produces bytes
2. Bytes get converted into a field element
3. Verifier receives the number

**What actually happens:**
1. Transcript creates a `Poseidon` node (the symbolic "result"), stores it in `PENDING`
2. Transcript returns dummy bytes through the official channel
3. The deserialization function ignores the bytes, reads from `PENDING`, gets the `MleAst`
4. Verifier receives the symbolic expression — a pointer to the `Poseidon` node

The verifier now has an `MleAst` that represents "the challenge." If the verifier later computes `challenge * something`, that creates a `Mul` node whose left child is the `Poseidon` node. The dependency is captured in the graph structure.

---

## Why This Works (And Why It's Ugly)

This is, admittedly, a hack. We're exploiting the gap between what an interface *specifies* (serialize to bytes, deserialize from bytes) and what it *checks* (very little — it trusts the implementations). The bytes are meaningless; the actual data moves through hidden global state.

But it's a *contained* hack. The ugliness is isolated to two places: `MleAst`'s serialization methods and the symbolic transcript's append/challenge methods. The rest of the codebase — including the entire Jolt verifier — remains clean. It calls `transcript.append_scalar(&x)` and `transcript.challenge_scalar()` exactly as it would with real field elements. The symbolic semantics are invisible at the call sites.

This lets us reuse the exact `Transcript` trait that the real verifier uses, without forking the codebase or adding special cases.

---

## The Hash as Symbolic Node

When the real Poseidon transcript hashes something, three values enter: the current state, a round counter (for domain separation), and the new data. The output becomes the new state, and the cycle continues.

The symbolic transcript creates nodes with the same structure:

```rust
fn hash_and_update(&mut self, element: MleAst) {
    let round = MleAst::from_i128(self.n_rounds as i128);
    self.state = MleAst::poseidon(&self.state, &round, &element);
    self.n_rounds += 1;
}
```

Each call adds a `Poseidon(state, round, data)` node to the arena. The transcript's state becomes a pointer to this new node. Subsequent hashes chain off it, building a linked structure:

```
Poseidon(Poseidon(Poseidon(init, 0, data_0), 1, data_1), 2, data_2)
```

When you derive a challenge, the tree at that point becomes the challenge value. Anything the verifier does with that challenge — multiplying by it, adding it to something else — creates more nodes that reference the challenge. The cryptographic dependency is captured structurally.

---

## From Tree to Circuit

Once you have the tree, generating Gnark code is mechanical. Walk the nodes, emit the corresponding API calls:

| AST Node | Gnark Output |
|----------|--------------|
| `Add(a, b)` | `api.Add(a, b)` |
| `Mul(a, b)` | `api.Mul(a, b)` |
| `Neg(a)` | `api.Neg(a)` |
| `Inv(a)` | `api.Inverse(a)` |
| `Poseidon(s, r, d)` | `poseidon.Hash(api, s, r, d)` |

The codegen adds **common subexpression elimination** (CSE). If a node is referenced multiple times — say, the same Poseidon hash appears in several places — it gets computed once and stored in a variable:

```go
cse_0 := poseidon.Hash(api, state, 0, data)
cse_1 := api.Mul(cse_0, circuit.X_0)
cse_2 := api.Add(cse_0, circuit.X_1)  // cse_0 reused
```

Without CSE, Poseidon chains would be inlined everywhere they're used, exploding the circuit size. With CSE, shared subexpressions are computed once.

---

## The Full Pipeline

The entry point is `gnark-transpiler/src/main.rs`. Here's the flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. SETUP                                                           │
│     ┌──────────────────┐    ┌──────────────────────┐                │
│     │ Symbolic Inputs  │    │ Symbolic Transcript  │                │
│     │ Var(0), Var(1)...│    │ (empty, state = 0)   │                │
│     └────────┬─────────┘    └──────────┬───────────┘                │
│              │                         │                            │
│              └────────────┬────────────┘                            │
│                           ▼                                         │
├─────────────────────────────────────────────────────────────────────┤
│  2. RUN VERIFIER                                                    │
│     ┌───────────────────────────────────────────────────────────┐   │
│     │  Jolt Verifier (unmodified Rust code)                     │   │
│     │                                                           │   │
│     │  • Does field arithmetic → creates Add, Mul nodes         │   │
│     │  • Calls transcript.append_scalar() → creates Poseidon    │   │
│     │  • Calls transcript.challenge_scalar() → returns Poseidon │   │
│     │  • Loops, branches, function calls → all execute normally │   │
│     │                                                           │   │
│     │  Arena grows: [Var(0), Var(1), Add(...), Poseidon(...)]   │   │
│     └───────────────────────────────────────────────────────────┘   │
│                           │                                         │
│                           ▼                                         │
├─────────────────────────────────────────────────────────────────────┤
│  3. EXTRACT RESULT                                                  │
│     Verifier returns: MleAst #4721 (index of final expression)     │
│     This expression must equal zero for valid proofs               │
│                           │                                         │
│                           ▼                                         │
├─────────────────────────────────────────────────────────────────────┤
│  4. GENERATE CODE                                                   │
│     Walk AST from root #4721, emit Gnark code, apply CSE           │
│     Output: verifier_circuit.go                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Step 1: Setup.** Create symbolic inputs — `Var(0)`, `Var(1)`, etc. — representing the proof data that will be provided at verification time. Create an empty symbolic transcript with initial state.

**Step 2: Run the verifier.** This is where the magic happens. The actual Jolt verification logic executes — the same Rust code that would run in production. But it's operating on `MleAst` values instead of real field elements, and using our symbolic transcript instead of a real one.

The verifier doesn't know it's being traced. It calls `transcript.append_scalar(&x)` when it wants to hash something — our transcript intercepts this and creates a Poseidon node. It calls `transcript.challenge_scalar()` when it wants a random challenge — our transcript returns an MleAst pointing to a Poseidon node. The transcript grows *during* verification, not before.

Every operation the verifier performs adds nodes to the arena. By the time verification finishes, the arena contains the complete computation graph.

**Step 3: Extract the result.** The verifier returns a symbolic expression — an MleAst index — representing the final check. In a valid proof, this expression should equal zero.

**Step 4: Generate code.** Walk the AST starting from the root, emit Gnark API calls, apply CSE to avoid recomputing shared subexpressions, write the `.go` file.

The output is a complete Gnark circuit that computes exactly what the Rust verifier computes — because it was *traced* from the Rust verifier, not translated by hand.

---

## What Could Go Wrong

**Poseidon parameter mismatch.** The real verifier uses `light-poseidon` with specific parameters — a particular MDS matrix and round constants (the circom-compatible ones). The Gnark code uses `vocdoni/gnark-crypto-primitives/poseidon`. If these use different parameters, the hash outputs differ, challenges differ, and valid proofs get rejected. This is the most critical thing to verify before deployment.

**Byte ordering.** The real transcript reverses bytes for EVM compatibility. The symbolic transcript works with field elements directly. For pure arithmetic, this doesn't matter — the AST captures structure, not byte representations. But if the Gnark circuit must match the real transcript's byte-level behavior, there could be subtle divergences.

**Stubbed methods.** Some transcript operations are placeholders:

```rust
fn append_point<G: CurveGroup>(&mut self, _point: &G) {
    self.hash_and_update(MleAst::from_i128(0));  // Ignores the point!
}
```

This works for Stage 1 verification, which is pure polynomial arithmetic. The full verifier would need complete implementations.

**Arena growth.** The global arena never clears. Multiple transpilation runs in the same process accumulate nodes. The snapshots include stale data from previous runs. Not a correctness issue — roots still point to valid subgraphs — but wasteful.

---

## What This Enables

The transpiler converts Jolt's Rust verifier into a Gnark circuit automatically. Change the Rust, rerun transpilation, get an updated circuit. The translation never drifts from the source.

But the approach generalizes beyond Gnark. The AST is a neutral intermediate representation. Different backends could emit:

- **Circom**: The other major circuit DSL
- **Noir**: Aztec's Rust-like proving language
- **Lean 4**: For formal verification (zkLean's original purpose)
- **Raw R1CS**: Skip the DSL, emit constraints directly

The hard part — capturing *what* the verifier does — happens once. Code generation is just tree-walking with different output syntax.

The current scope is Stage 1: the Spartan outer sumcheck, pure polynomial arithmetic. The full Jolt verifier includes inner sumchecks, polynomial commitments (Dory), and lookup arguments (Lasso). Each brings new challenges. Commitments involve elliptic curve operations that don't fit cleanly into field arithmetic. Lookups have complex constraint structures. But the foundation — symbolic execution through operator overloading — extends naturally.

---

## Summary

To translate code, you don't have to understand it statically. You can watch it run.

Jolt's verifier is generic over field types. We provide a type that records operations instead of computing them. The same code executes, but the meaning of each operation changes. Where `Fr::mul` computes a product, `MleAst::mul` records "multiply these two expressions."

Run the verifier with symbolic inputs, get a tree describing the computation. Walk the tree, emit circuit code. The translation is faithful by construction — it's a trace of what actually happens, not an interpretation of what the source code says.

This is the difference between analyzing a machine and observing one. The first requires understanding every gear. The second just requires watching it work.
