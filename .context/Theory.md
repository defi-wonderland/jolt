# Understanding Code Extraction: Runtime Introspection (Symbolic Execution) vs Static Analysis

## Table of Contents

1. [What is zkLean?](#what-is-zklean)
2. [Static Analysis Explained](#static-analysis-explained)
3. [Runtime Introspection Explained](#runtime-introspection-explained)
4. [The zkLean Implementation](#the-zklean-implementation)
5. [Application to Groth16 Conversion](#application-to-groth16-conversion)

---

## What is zkLean?

**zkLean** is a tool developed for the Jolt zkVM project that extracts verification logic from Rust code and converts it into Lean 4 code for formal verification.

### The Problem It Solves

Zero-knowledge proof systems are complex cryptographic protocols. Bugs in the implementation can:
- Break soundness (accept invalid proofs)
- Break completeness (reject valid proofs)
- Create security vulnerabilities

Manual verification is error-prone and doesn't scale.

### The Solution

zkLean automatically:
1. **Extracts** the mathematical operations from Jolt's Rust verifier code
2. **Translates** them into Lean 4 (a proof assistant language)
3. **Enables formal verification** that the implementation matches the mathematical specification

### Why Lean?

Lean 4 is a theorem prover that allows mathematicians and computer scientists to:
- Write formal proofs that are machine-checkable
- Verify properties like soundness and completeness mathematically
- Ensure the implementation exactly matches the specification

### zkLean's Role in Jolt

The Jolt team uses zkLean to verify their polynomial IOPs (Interactive Oracle Proofs):
- Lasso (lookup arguments)
- Spartan (constraint system verification)
- Spice (decomposition protocol)

This provides much higher assurance than testing alone.

---

## Static Analysis Explained

**Static analysis** means examining source code **without running it**. You analyze the text/structure of the code itself.

### How It Works

A static analyzer:
1. **Parses** source code into an Abstract Syntax Tree (AST)
2. **Analyzes** the structure, types, and control flow
3. **Extracts** information or transforms the code

### Example: Static Analysis

```rust
fn compute(a: i32, b: i32) -> i32 {
    let c = a + b;
    if c > 10 {
        c * 2
    } else {
        c + 5
    }
}
```

A static analyzer sees:
- **Function signature**: `fn compute(a: i32, b: i32) -> i32`
- **Variable `c`**: type `i32`, computed as `a + b`
- **Conditional branch**: two possible execution paths
- **Return values**: `c * 2` or `c + 5`

It can extract:
```
Function: compute
Inputs: a (i32), b (i32)
Operations:
  - c = a + b
  - if c > 10:
      - return c * 2
  - else:
      - return c + 5
```

### Advantages of Static Analysis

1. **Complete view**: Sees all code paths, even unreachable ones
2. **No execution needed**: Works on any valid source code
3. **Language tooling**: Can use existing parsers (like `syn` for Rust)
4. **Type information**: Has access to full type system

### Disadvantages of Static Analysis

1. **Complexity**: Must understand the entire language (Rust is complex!)
2. **Type resolution**: Generics, trait bounds, and macros are hard to resolve
3. **Indirect operations**: Method calls through traits require complex tracking
4. **Macros**: Rust macros can generate arbitrary code at compile time
5. **Implementation burden**: Requires building a sophisticated parser/analyzer

### For Jolt Specifically

Static analysis of Jolt's verifier would require:
- Parsing generic Rust code with complex trait bounds
- Resolving `JoltField` implementations across multiple types
- Tracking method calls through trait objects
- Understanding macro expansions
- Handling conditional compilation (`#[cfg(...)]`)

This is technically feasible but requires significant engineering effort.

---

## Runtime Introspection Explained

**Runtime Introspection** (also called **Symbolic Execution** or **Symbolic Evaluation**) means running code with special types that **record operations** instead of executing them.

### The Core Idea

Instead of analyzing source code, you:
1. **Swap out** concrete types with "recording" types
2. **Execute** the code normally
3. **Capture** a trace of all operations performed

It's like running code with a "tape recorder" that logs every operation.

### Analogy: Calculator Trace

Normal calculator usage:
```
Input: 3 + 5
Output: 8
```

Calculator with recording:
```
Input: 3 + 5
Output: 8
Trace: [ADD(3, 5) → 8]
```

For complex expressions:
```
Input: (3 + 5) * 2
Output: 16
Trace: [
  ADD(3, 5) → 8,
  MUL(8, 2) → 16
]
```

### Key Difference from Static Analysis

| Aspect | Static Analysis | Runtime Introspection |
|--------|----------------|----------------------|
| Code execution | Never runs | Actually runs |
| What it sees | All code paths | Only executed paths |
| Input needed | Source code | Runnable code + symbolic inputs |
| Complexity | High (must parse language) | Lower (just implement traits) |
| Completeness | Sees everything | Sees only what executes |

### How It Works: The Trick

Most code is **generic** over types:

```rust
fn compute<T: Numeric>(a: T, b: T) -> T {
    let c = a + b;
    c * a
}
```

You can run this with:
- **Concrete type**: `compute(3i32, 5i32)` → computes `24`
- **Recording type**: `compute(Recorder::var("a"), Recorder::var("b"))` → records AST

The **same code** behaves differently based on the type!

### Simple Example

```rust
// Recording type
struct Recorder {
    operations: Vec<Op>,
}

impl Add for Recorder {
    fn add(self, other: Self) -> Self {
        self.operations.push(Op::Add(self.id, other.id));
        // Return new recorder with combined operations
        Recorder { operations: self.operations }
    }
}

// Usage
let a = Recorder::var("a");  // operations: []
let b = Recorder::var("b");  // operations: []
let c = a + b;               // operations: [Add(a, b)]
```

After "execution", `c.operations` contains the complete trace!

### Common Questions About Runtime Introspection (Symbolic Execution)

#### Q1: What if code is not generic over types?

If code uses concrete types directly, you have two options:

**Option 1: Add generics** (if you control the code)
```rust
// Before: concrete type
fn verify(a: BN254Field, b: BN254Field) -> BN254Field {
    a + b * a
}

// After: generic
fn verify<F: JoltField>(a: F, b: F) -> F {
    a + b * a
}
```

**Option 2: Replace at call sites** (if you can't modify the function)
```rust
// Original code with concrete types
fn internal_compute(x: BN254Field) -> BN254Field {
    x * x + x
}

// Wrapper that works with any field
fn compute_generic<F: JoltField>(x: F) -> F {
    // Manually translate the operations
    let squared = x * x;
    squared + x
}
```

For Jolt specifically, most verifier code is already generic over `JoltField`, which is why runtime introspection works well.

#### Q2: What are `OnceLock<RwLock<Vec<Node>>>` types?

These are Rust concurrency primitives that work together:

**`Vec<Node>`**: A growable array storing all AST nodes
```rust
Vec<Node> = [
    Node::Atom("a"),
    Node::Atom("b"),
    Node::Add(0, 1),  // refers to nodes at index 0 and 1
]
```

**`RwLock<Vec<Node>>`**: A read-write lock allowing multiple readers OR one writer
- Multiple threads can read the arena simultaneously
- Only one thread can modify it at a time
- Prevents race conditions

**`OnceLock<RwLock<Vec<Node>>>`**: Lazy initialization that happens once
- First access initializes the arena
- Subsequent accesses reuse the same arena
- Thread-safe initialization

```rust
static ARENA: OnceLock<RwLock<Vec<Node>>> = OnceLock::new();

// First call initializes
let arena = ARENA.get_or_init(|| RwLock::new(Vec::new()));

// Subsequent calls return the same arena
let arena = ARENA.get().unwrap();
```

This pattern allows a global mutable arena without `unsafe` code.

#### Q3: What is a "node"?

A **node** is one element in the Abstract Syntax Tree (AST). Each node represents either:
- A **leaf**: variable, constant, or named value
- An **operation**: addition, multiplication, etc.

```rust
enum Node {
    // Leaves
    Atom(Atom),           // variable "x", constant 5, etc.

    // Unary operations
    Neg(Edge),            // -x
    Inv(Edge),            // 1/x

    // Binary operations
    Add(Edge, Edge),      // a + b
    Mul(Edge, Edge),      // a * b
    Sub(Edge, Edge),      // a - b
    Div(Edge, Edge),      // a / b
}
```

Example AST for `(a + b) * a`:
```
Node 0: Atom("a")
Node 1: Atom("b")
Node 2: Add(Node 0, Node 1)     // a + b
Node 3: Mul(Node 2, Node 0)     // (a + b) * a
```

The tree structure:
```
      Mul (Node 3)
      /  \
   Add    a
   / \
  a   b
```

#### Q4: Is symbolic execution faster than concrete execution?

**No, symbolic execution is slower.** Here's why:

**Concrete execution** (with real numbers):
```rust
let result = 3 + 5;  // Direct CPU operation: ~1 nanosecond
```

**Symbolic execution** (with recording):
```rust
let result = MleAst::var("a") + MleAst::var("b");
// Does:
// 1. Lock the arena (thread synchronization)
// 2. Create new Node::Add
// 3. Allocate memory in Vec
// 4. Update references
// ~100-1000 nanoseconds
```

**Performance comparison:**
- Concrete field operations: 1-10 ns
- Symbolic recording: 100-1000 ns (10-100x slower)

**But**: We only run symbolic execution **once** to extract the circuit, not in production. The slowdown is acceptable for a one-time extraction.

#### Q5: Is the arena accessed on every operation?

**Yes**, but it's optimized:

Every field operation:
1. Acquires write lock on arena
2. Pushes new node to `Vec`
3. Releases lock

```rust
impl Add for MleAst {
    fn add(self, rhs: Self) -> Self {
        // Lock acquired here
        let mut arena = ARENA.get().unwrap().write().unwrap();

        let new_node = Node::Add(self.edge(), rhs.edge());
        let new_id = arena.len();
        arena.push(new_node);  // Amortized O(1)

        // Lock released here
        MleAst { node_id: new_id }
    }
}
```

**Why this is acceptable:**
- `Vec::push` is amortized O(1) (occasional reallocation)
- Lock contention is minimal (single-threaded extraction)
- No tree reconstruction; we only append to the `Vec`
- References are just `usize` indices (cheap to copy)

The tree is **never reconstructed**; nodes are added incrementally and old nodes never move.

---

## The zkLean Implementation

Now let's see how zkLean actually implements runtime introspection (symbolic execution) for Jolt.

### 1. Normal Jolt Code

Jolt's verifier performs many field operations:

```rust
fn verify_something(a: Field, b: Field) -> Field {
    let c = a + b;
    let d = c * a;
    d.square()
}
```

Normally this computes concrete values: `3 + 5 = 8`, then `8 * 3 = 24`, etc.

### 2. The Instrumented Type: `MleAst`

zkLean creates a special type `MleAst` that **looks exactly like a field element**, but internally:
- **Doesn't perform computation**
- **Creates an AST node** for each operation

```rust
struct MleAst {
    node_id: NodeId,  // Reference to an AST node
}

enum Node {
    Atom(Atom),           // Constant or variable
    Add(Edge, Edge),      // Addition
    Mul(Edge, Edge),      // Multiplication
    Neg(Edge),            // Negation
    Inv(Edge),            // Inversion
    // ... etc
}
```

### 3. The JoltField Trait

Jolt's code is generic over `JoltField`:

```rust
trait JoltField {
    fn add(self, other: Self) -> Self;
    fn mul(self, other: Self) -> Self;
    // ... etc
}
```

Normally this is implemented by concrete fields like `BN254Field`.

**But**: `MleAst` **also** implements `JoltField`!

```rust
impl JoltField for MleAst {
    fn add(self, rhs: Self) -> Self {
        // Don't compute the result,
        // create a new AST node instead:
        let new_node = Node::Add(
            Edge::NodeRef(self.node_id),
            Edge::NodeRef(rhs.node_id)
        );
        let new_id = GLOBAL_ARENA.push(new_node);
        MleAst { node_id: new_id }
    }
}
```

### 4. The Trick: Execute Code with Instrumented Type

Now the **key insight**:

```rust
// Original Jolt code (unchanged):
fn verify_something<F: JoltField>(a: F, b: F) -> F {
    let c = a + b;
    let d = c * a;
    d.square()
}

// Normal usage:
let result = verify_something(
    BN254Field::from(3),
    BN254Field::from(5)
);
// => Actually computes: 64

// zkLean usage:
let ast = verify_something(
    MleAst::variable("a"),
    MleAst::variable("b")
);
// => Creates AST: square(mul(add(a, b), a))
```

## The Global Arena

Problem: How do you store a growing tree when `MleAst` must be `Copy`?

**Solution**: Global arena with `OnceLock<RwLock<Vec<Node>>>`:

```rust
static GLOBAL_ARENA: OnceLock<RwLock<Vec<Node>>> = OnceLock::new();

impl MleAst {
    fn binop(&mut self, op: NodeConstructor, rhs: &Self) {
        let new_node = op(self.edge(), rhs.edge());
        let mut arena = GLOBAL_ARENA.get().unwrap().write().unwrap();
        let new_id = arena.len();
        arena.push(new_node);
        self.node_id = new_id;
    }
}
```

All AST nodes live in this arena. `MleAst` is just a `NodeId` (index).

## Complete Workflow

### Step 1: Instrument

```rust
// Create "symbolic" inputs:
let x = MleAst::variable("x");
let y = MleAst::variable("y");
```

### Step 2: Execute Code

```rust
// Call Jolt's verifier code:
let result = jolt_verifier.combine_lookups(x, y);
```

The code **actually runs**, but:
- Instead of computing, it builds an AST
- Each operation (`+`, `*`, etc.) adds a node

### Step 3: Extract AST

```rust
// After "execution":
let ast_graph = GLOBAL_ARENA.get().unwrap().read().unwrap();
```

Now you have a complete graph of all operations!

### Step 4: Convert to Target Language

After extraction, the AST is translated into the target language (Lean, Gnark, etc.). This is a **tree traversal** that outputs code in the target syntax.

#### How Translation Works

The translator walks the AST recursively, converting each node to target language syntax:

```rust
fn format_for_lean(&self, arena: &[Node]) -> String {
    let node = &arena[self.node_id];
    match node {
        Node::Atom(var) => var.to_string(),  // "a" → "a"

        Node::Add(left, right) => {
            let left_code = left.format_for_lean(arena);
            let right_code = right.format_for_lean(arena);
            format!("({} + {})", left_code, right_code)
        },

        Node::Mul(left, right) => {
            let left_code = left.format_for_lean(arena);
            let right_code = right.format_for_lean(arena);
            format!("({} * {})", left_code, right_code)
        },

        Node::Neg(child) => {
            let child_code = child.format_for_lean(arena);
            format!("(-{})", child_code)
        },

        // ... other operations
    }
}
```

#### Example: Step-by-Step Translation

AST for `(a + b) * a`:
```
Node 0: Atom("a")
Node 1: Atom("b")
Node 2: Add(Node 0, Node 1)
Node 3: Mul(Node 2, Node 0)
```

Translation process:
```rust
// Start at root (Node 3)
format_for_lean(Node 3)
  → Node 3 is Mul(Node 2, Node 0)
  → Left: format_for_lean(Node 2)
      → Node 2 is Add(Node 0, Node 1)
      → Left: format_for_lean(Node 0)
          → Node 0 is Atom("a")
          → Returns "a"
      → Right: format_for_lean(Node 1)
          → Node 1 is Atom("b")
          → Returns "b"
      → Returns "(a + b)"
  → Right: format_for_lean(Node 0)
      → Returns "a"
  → Returns "((a + b) * a)"
```

Final output:
```lean
def verify_something (a b : Field) : Field :=
  ((a + b) * a)
```

#### Target Language Mapping

Different targets have different syntax:

| Operation | AST Node | Lean Output | Gnark Output (Go) |
|-----------|----------|-------------|-------------------|
| Add | `Add(a, b)` | `(a + b)` | `api.Add(a, b)` |
| Multiply | `Mul(a, b)` | `(a * b)` | `api.Mul(a, b)` |
| Negate | `Neg(a)` | `(-a)` | `api.Neg(a)` |
| Inverse | `Inv(a)` | `(a⁻¹)` | `api.Inverse(a)` |

For Gnark:
```rust
fn format_for_gnark(&self, arena: &[Node]) -> String {
    let node = &arena[self.node_id];
    match node {
        Node::Add(l, r) => format!("api.Add({}, {})",
            l.format_for_gnark(arena),
            r.format_for_gnark(arena)
        ),
        Node::Mul(l, r) => format!("api.Mul({}, {})",
            l.format_for_gnark(arena),
            r.format_for_gnark(arena)
        ),
        // ... etc
    }
}
```

Output:
```go
func VerifySomething(api frontend.API, a, b frontend.Variable) frontend.Variable {
    temp1 := api.Add(a, b)
    result := api.Mul(temp1, a)
    return result
}
```

#### Handling Complex Structures

For larger expressions, the translator can:
1. **Inline everything** (simple but verbose)
2. **Use let-bindings** (create temporary variables)
3. **Create helper functions** (for repeated patterns)

Example with let-bindings:
```lean
def complex_verify (a b c : Field) : Field :=
  let sum := a + b
  let prod := sum * c
  let final := prod + sum
  final
```

This is crucial for readability and performance in the target language.

## Optimizations in PR #1060

PR #1060 addressed critical performance problems that made the initial zkLean implementation impractical for large polynomials.

### Problem: Exponential Growth

Without optimization, repeated subexpressions cause exponential code blowup:

**Example**: Computing `x²` three times
```rust
let a = x * x;      // x appears 2 times
let b = a * a;      // x appears 4 times (2 * 2)
let c = b * b;      // x appears 16 times (4 * 4)
```

Naive translation:
```lean
-- Completely inlined (exponential in depth):
((x * x) * (x * x)) * ((x * x) * (x * x))
-- This is 8 multiplications instead of 3!
```

For Jolt's 64-bit lookup tables with polynomial MLEs of depth 20+, this causes:
- **Gigabytes** of generated Lean code
- **Years** of Lean compilation time (literally)
- **Memory exhaustion** during type checking

### Solution 1: Common Subexpression Elimination (CSE)

**Idea**: Identify duplicate subexpressions and create let-bindings for them.

#### Algorithm

```rust
fn apply_cse(&mut self, threshold: usize) {
    let mut seen = HashMap::new();
    let mut usage_count = HashMap::new();

    // Pass 1: Count how many times each subexpression appears
    for (id, node) in self.arena.iter().enumerate() {
        *usage_count.entry(node.clone()).or_insert(0) += 1;
    }

    // Pass 2: Assign names to frequently-used subexpressions
    for (id, node) in self.arena.iter().enumerate() {
        if usage_count[node] >= threshold {
            if let Some(&first_id) = seen.get(node) {
                // This is a duplicate; point to the first occurrence
                self.replacements.insert(id, first_id);
            } else {
                // First occurrence; remember it
                seen.insert(node.clone(), id);
                if usage_count[node] > 1 {
                    self.let_bindings.insert(id, format!("temp_{}", id));
                }
            }
        }
    }
}
```

#### Before CSE

```lean
def polynomial (x y : Field) : Field :=
  ((x + y) * x) + ((x + y) * y) + ((x + y) * (x + y))
```

Each `(x + y)` is computed separately.

#### After CSE

```lean
def polynomial (x y : Field) : Field :=
  let sum := x + y
  let prod_x := sum * x
  let prod_y := sum * y
  let prod_sum := sum * sum
  prod_x + prod_y + prod_sum
```

Now `(x + y)` is computed **once** and reused.

**Impact**: For Jolt's 64-bit MLEs, CSE reduced generated code size from **~100GB to ~100MB**.

### Solution 2: Top-Level Definitions

Even with CSE, large let-bindings can cause performance issues in Lean's type checker.

**Problem**: Lean's type checker has quadratic complexity for deeply nested let-bindings.

```lean
-- This takes O(n²) time to type-check:
def big_polynomial :=
  let a := x + y
  let b := a * a
  let c := b * b
  let d := c * c
  -- ... 1000 more bindings
  d
```

**Solution**: Hoist common subexpressions to top-level definitions.

#### Algorithm

```rust
fn extract_top_level_defs(&self, depth_threshold: usize) -> Vec<(String, String)> {
    let mut defs = Vec::new();

    for (id, node) in self.arena.iter().enumerate() {
        let depth = self.compute_depth(id);

        if depth > depth_threshold || self.usage_count[id] > 2 {
            let def_name = format!("subexpr_{}", id);
            let def_body = self.format_node(id);
            defs.push((def_name, def_body));
        }
    }

    defs
}
```

#### Before Top-Level Extraction

```lean
def verify_mle (x₀ x₁ x₂ : Field) : Field :=
  let a := complicated_expr₁
  let b := complicated_expr₂
  let c := complicated_expr₃
  -- ... 1000 more let bindings
  final_expr
```

Lean must re-check each let-binding in context.

#### After Top-Level Extraction

```lean
-- Top-level definitions (checked independently)
def subexpr_42 (x₀ x₁ x₂ : Field) : Field :=
  complicated_expr₁

def subexpr_83 (x₀ x₁ x₂ : Field) : Field :=
  complicated_expr₂

def subexpr_107 (x₀ x₁ x₂ : Field) : Field :=
  complicated_expr₃

-- Main definition (much simpler)
def verify_mle (x₀ x₁ x₂ : Field) : Field :=
  let a := subexpr_42 x₀ x₁ x₂
  let b := subexpr_83 x₀ x₁ x₂
  let c := subexpr_107 x₀ x₁ x₂
  final_expr
```

Each top-level definition is type-checked **once** and **independently**. The main function just calls them.

**Impact**: Compile time reduced from **2+ years to 10 minutes**.

### Solution 3: Arena Allocation

Early versions used recursive `Box<Node>` structures:

```rust
// Old (causes stack overflow):
enum Node {
    Add(Box<Node>, Box<Node>),
    Mul(Box<Node>, Box<Node>),
}
```

For deep expressions (depth 64+), this caused:
- **Stack overflow** during construction
- **Heap fragmentation**
- **Cache-unfriendly** access patterns

**Solution**: Use an arena with indices:

```rust
// New (flat storage):
struct MleAst {
    node_id: usize,  // Index into arena
}

static ARENA: OnceLock<RwLock<Vec<Node>>> = OnceLock::new();
```

All nodes are stored in a contiguous `Vec`, referenced by index. Benefits:
- **No recursion** during construction
- **Cache-friendly** sequential access
- **O(1) copy** (just copy the index)

### Combined Impact

| Metric | Before Optimizations | After Optimizations |
|--------|---------------------|---------------------|
| Generated code size | ~100 GB | ~100 MB |
| Lean compile time | >2 years | ~10 minutes |
| Memory usage | Exhausts 64GB RAM | ~2GB RAM |
| Stack depth | Overflows at depth 20 | No limit |

These optimizations made zkLean **practical** for extracting Jolt's 64-bit lookup table MLEs.

### Why "zkLean"?

The name "zkLean" combines two elements:

1. **"zk"**: Zero-knowledge (the domain - extracting ZK proof system verification logic)
2. **"Lean"**: Lean 4 (the target language for formal verification)

**There's no special "zk" modification to Lean itself**. The name just indicates:
- It's a tool for ZK systems
- It outputs Lean code
- It's part of the Jolt zkVM ecosystem

It could have been called "jolt-lean-extractor" or "lean-extractor", but "zkLean" is shorter and emphasizes the ZK proof verification use case.

### Important: zkLean vs Groth16 Conversion

**zkLean and the Groth16 conversion project are separate efforts with different goals:**

| Aspect | zkLean (existing) | Groth16 Conversion (this project) |
|--------|------------------|-----------------------------------|
| **Target** | Lean 4 | Gnark/Go |
| **Purpose** | Formal verification | On-chain verification |
| **Goal** | Prove correctness properties | Generate compact proofs |
| **Output** | Lean theorems | Groth16 circuits |
| **Use case** | Mathematical verification | Blockchain deployment |

**Why we study zkLean:** The extraction technique (runtime introspection/symbolic execution, AST building, optimizations) is directly applicable. We'd reuse the same approach but change the output target:

```rust
// zkLean does this:
fn format_for_lean(&self) -> String {
    // Generate Lean code
}

// We'd do this instead:
fn format_for_gnark(&self) -> String {
    // Generate Gnark/Go code
}
```

The **extraction infrastructure** (MleAst, arena, CSE, etc.) is the same. Only the **code generation** differs.

---

## Comparison to Static Parsing

| Runtime Introspection (Symbolic Execution) | Static Parsing |
|----------------------|----------------|
| Code **actually runs** | Code is **analyzed** |
| Only needs trait implementation | Must understand Rust syntax |
| Automatically follows all code paths | Must analyze control flow |
| Only sees what executes | Sees entire code |
| Simpler to implement | Complex (Rust type system!) |
| Used by zkLean | Theoretical approach |

## Practical Example from Jolt

In PR #1060:

```rust
// Jolt's lookup table code:
impl<F: JoltField> LookupTable for AddTable {
    fn evaluate_mle(&self, point: &[F]) -> F {
        let (x, y) = decompose_operands(point);
        let result = x + y;
        // ... more logic
        result
    }
}

// zkLean calls with MleAst:
let ast_result = AddTable.evaluate_mle(&[
    MleAst::variable("x"),
    MleAst::variable("y")
]);

// ast_result now contains the AST for the entire computation!
// This is then output as Lean code.
```

## Application to Groth16 Conversion

For Groth16 conversion, we'd use the same symbolic execution approach:

### Pipeline

1. **Instrument Jolt verifier**: Use `MleAst` (or equivalent) instead of concrete field
2. **Execute verifier logic**: Builds AST of all operations
3. **Extract constraint system**: Convert AST to R1CS constraints
4. **Generate Gnark code**: Translate constraints to Gnark/Go syntax
5. **Compile Groth16 circuit**: Use Gnark to generate proving system

### Advantages

1. **No manual translation**: Code runs, AST is automatically created
2. **Always in sync**: If Jolt changes, just regenerate
3. **No code drift**: AST comes directly from actual code
4. **Maintainable**: No complex parser infrastructure

### Adaptation for Gnark

Instead of outputting Lean:

```rust
fn format_for_gnark(&self) -> String {
    match self.node {
        Node::Add(a, b) => format!("api.Add({}, {})",
            a.format_for_gnark(),
            b.format_for_gnark()
        ),
        Node::Mul(a, b) => format!("api.Mul({}, {})",
            a.format_for_gnark(),
            b.format_for_gnark()
        ),
        // ... etc
    }
}
```

Output:
```go
func VerifySomething(api frontend.API, a, b frontend.Variable) frontend.Variable {
    c := api.Add(a, b)
    d := api.Mul(c, a)
    return api.Mul(d, d)
}
```

## Key Implementation Challenges

### 1. Field Compatibility

Jolt uses specific fields (e.g., BN254). Gnark circuits must use compatible fields for constraint generation.

### 2. Non-Determinism

Some verifier operations use randomness or hints. These need special handling:
- Hints become circuit inputs
- Randomness becomes Fiat-Shamir derived values

### 3. Polynomial Commitments

Commitment scheme operations (Hyrax/Dory PCS) are expensive in circuits. PR #975's hint approach helps here.

### 4. Circuit Size

The resulting R1CS constraint count determines feasibility. Optimizations from PR #975 and future lattice PCS integration are critical.

## References

- [PR #1060: zkLean Extractor for 64-bit Twist & Shout](https://github.com/a16z/jolt/pull/1060)
- [PR #975: Hint-based verification optimizations](https://github.com/a16z/jolt/pull/975)
- [Jolt formal verification efforts (a16z crypto)](https://a16zcrypto.com/posts/article/getting-bugs-out-of-snarks/)