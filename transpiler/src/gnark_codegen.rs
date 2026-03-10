//! Gnark/Go code generation from MleAst symbolic expressions.
//!
//! # Overview
//!
//! This module converts the AST (Abstract Syntax Tree) built during symbolic execution
//! into Gnark circuit code. The AST represents all arithmetic operations performed by
//! the Jolt verifier, and this module emits equivalent Go code using gnark's API.
//!
//! # Target Coupling
//!
//! This codegen emits hardcoded Go syntax and gnark API calls. It would need updates if:
//!
//! - **Go syntax changes** (unlikely, Go has strong backward compatibility)
//! - **gnark API changes** (e.g., `api.Add()` renamed, `frontend.Variable` changed)
//! - **Our poseidon package changes** (function signatures in `jolt_verifier/poseidon`)
//! - **New AST primitives added** (new `Node` variants require new codegen cases)
//!
//! The coupling is intentional: we emit target-specific code for gnark. If we add other
//! targets (Circom, Plonky2), they'd need separate codegen modules.
//!
//! Currently targets: **gnark v0.10.x** with Go 1.21+
//!
//! # Key Components
//!
//! - [`GnarkCodeGen`]: The main code generator with CSE (Common Subexpression Elimination)
//! - [`generate_circuit_from_bundle`]: Entry point that generates a complete circuit file
//! - [`sanitize_go_name`]: Converts Rust identifiers to valid Go identifiers
//!
//! # Code Generation Pipeline
//!
//! 1. **Reference Counting**: First pass counts how many times each AST node is used
//! 2. **Post-Order Traversal**: Generate expressions bottom-up (children before parents)
//! 3. **CSE Hoisting**: Nodes used more than once become named variables (e.g., `cse_0_1`)
//! 4. **Per-Constraint Namespacing**: Each constraint gets isolated CSE to prevent aliasing bugs
//!
//! # Example Output
//!
//! ```go
//! // CSE bindings for constraint 0
//! cse_0_0 := api.Mul(circuit.Stage1_Sumcheck_R0_0, circuit.Stage1_Sumcheck_R0_1)
//! cse_0_1 := api.Add(cse_0_0, circuit.Stage1_Sumcheck_R0_2)
//!
//! // assertion_0
//! assertion_0 := api.Sub(cse_0_1, circuit.Expected_0)
//! api.AssertIsEqual(assertion_0, 0)
//! ```
//!
//! # Per-Constraint Expression Trees
//!
//! Each constraint (sumcheck assertion) gets its own isolated expression tree with
//! independent CSE namespacing: constraint 0 uses `cse_0_*`, constraint 1 uses `cse_1_*`, etc.
//!
//! **Why this architecture?** Easier debugging. When a constraint fails, its expression
//! tree is self-contained. You can trace through `cse_N_*` variables knowing they all
//! belong to constraint N, without cross-referencing expressions from other sumchecks.
//!
//! Note: Since each MleAst operation creates a unique NodeId in the arena (no structural
//! deduplication), there's no aliasing risk between constraints. The isolation is purely
//! for debugging convenience.

use std::collections::{BTreeMap, HashMap, HashSet};
use zklean_extractor::mle_ast::{
    scalar_add_mod, scalar_mul_mod, scalar_neg_mod, scalar_sub_mod, Atom, Edge, Node, Scalar,
    TargetField, TranscriptHashData,
};
use zklean_extractor::{G1Constraint, G1Op};

// =============================================================================
// Helper Functions
// =============================================================================

/// Extract child node IDs from a Node (used by generate_expr for traversal).
fn node_children(node: &Node) -> Vec<usize> {
    fn edge_to_child(edge: &Edge) -> Option<usize> {
        match edge {
            Edge::NodeRef(id) => Some(*id),
            Edge::Atom(_) => None,
        }
    }

    match node {
        Node::Atom(_) => vec![],
        Node::Neg(e)
        | Node::Inv(e)
        | Node::ByteReverse(e)
        | Node::Truncate128Reverse(e)
        | Node::Truncate128(e)
        | Node::AppendU64Transform(e) => edge_to_child(e).into_iter().collect(),
        Node::Add(e1, e2) | Node::Mul(e1, e2) | Node::Sub(e1, e2) | Node::Div(e1, e2) => {
            [edge_to_child(e1), edge_to_child(e2)]
                .into_iter()
                .flatten()
                .collect()
        }
        Node::TranscriptHash(hash_data, e1, e2) => {
            let mut v: Vec<usize> = [edge_to_child(e1), edge_to_child(e2)]
                .into_iter()
                .flatten()
                .collect();
            v.extend(hash_data.as_slice().iter().filter_map(edge_to_child));
            v
        }
    }
}

// =============================================================================
// Types
// =============================================================================

/// Statistics about constant assertions detected during codegen.
#[derive(Debug, Default)]
pub struct ConstantAssertionStats {
    /// Total number of constraints processed
    pub total_constraints: usize,
    /// Number of constant assertions that were skipped
    pub constant_skipped: usize,
    /// Number of constant assertions that failed (non-zero constant)
    pub constant_failed: usize,
    /// Names of failed constant assertions
    pub failed_names: Vec<String>,
    /// Whether poseidon was used (for import generation)
    pub uses_poseidon: bool,
}

/// Processed constraint data for code generation.
struct ProcessedConstraint {
    /// Constraint name (for comments and variable naming)
    name: String,
    /// Generated Go expression for the constraint's root
    expr: String,
    /// CSE bindings code for this constraint
    bindings: String,
    /// The assertion type
    assertion: ConstraintAssertion,
    /// Whether the expression is entirely constant
    is_const: bool,
    /// Evaluated constant value (if is_const is true)
    const_val: Option<[u64; 4]>,
}

/// Assertion type for processed constraints (owned version of Assertion).
#[allow(clippy::enum_variant_names)] // Mirrors zklean_extractor::mle_ast::Assertion naming
enum ConstraintAssertion {
    EqualZero,
    EqualPublicInput { name: String },
    EqualNode { other_expr: String },
}

/// Memoized code generator that converts AST nodes to Gnark expressions.
///
/// This struct maintains state for a single code generation pass:
/// - Tracks reference counts to determine which expressions to hoist
/// - Caches generated expressions to avoid regenerating subtrees
/// - Collects CSE bindings (named intermediate variables)
///
/// # Usage
///
/// ```ignore
/// let mut codegen = GnarkCodeGen::new(&bundle.nodes, var_names, constraint_idx);
/// codegen.count_refs(root_node_id);  // First pass: count references
/// let expr = codegen.generate_expr(root_node_id);  // Second pass: generate code
/// let bindings = codegen.bindings_code();  // Get CSE variable definitions
/// ```
///
/// # Per-Constraint Isolation
///
/// Create a fresh `GnarkCodeGen` for each constraint. This gives each sumcheck
/// its own expression tree with isolated CSE variables (`cse_N_*` for constraint N),
/// making debugging easier: when a constraint fails, all `cse_N_*` variables
/// belong to that constraint.
pub(crate) struct GnarkCodeGen<'a> {
    /// Reference to the node arena (from AstBundle.nodes)
    nodes: &'a [Node],
    /// Reference counts for each NodeId (computed in first pass)
    ref_counts: HashMap<usize, usize>,
    /// Maps NodeId to CSE variable name (e.g., "cse_0" or "cse_3_0" for constraint 3)
    generated: HashMap<usize, String>,
    /// CSE variable definitions in order
    bindings: Vec<String>,
    /// Next CSE variable index
    cse_counter: usize,
    /// Maps variable index to input name (e.g., 0 -> "UniSkipCoeff0")
    var_names: &'a HashMap<u16, String>,
    /// Constraint index for per-constraint CSE naming (e.g., constraint 3 uses cse_3_*)
    constraint_idx: usize,
    /// Whether poseidon was used in this constraint
    uses_poseidon: bool,
}

impl<'a> GnarkCodeGen<'a> {
    /// Create a GnarkCodeGen with pre-computed CSE bindings from AstBundle.
    ///
    /// CSE is computed at the AST level (via `AstBundle::run_cse()`) for:
    /// - Single CSE pass shared across all targets
    /// - Consistent CSE decisions for gnark, Lean4, etc.
    /// - Simpler codegen (just emit, no analysis)
    ///
    /// The `cse_bindings` slice contains NodeIds that should be hoisted, in order.
    /// They become `cse_{constraint_idx}_{i}` for element `i`.
    pub(crate) fn new(
        nodes: &'a [Node],
        var_names: &'a HashMap<u16, String>,
        constraint_idx: usize,
        cse_bindings: &[usize],
    ) -> Self {
        let mut ref_counts = HashMap::new();

        // Mark ref_counts > 1 for all CSE nodes so they get hoisted.
        // The hoisting order is determined by post-order traversal in generate_expr,
        // which matches the order CSE bindings were computed.
        for &node_id in cse_bindings {
            ref_counts.insert(node_id, 2);
        }

        Self {
            nodes,
            ref_counts,
            generated: HashMap::new(),
            bindings: Vec::new(),
            cse_counter: 0,
            var_names,
            constraint_idx,
            uses_poseidon: false,
        }
    }

    /// Returns whether poseidon was used in this constraint
    pub(crate) fn uses_poseidon(&self) -> bool {
        self.uses_poseidon
    }

    /// Get all CSE bindings as Go code
    pub(crate) fn bindings_code(&self) -> String {
        self.bindings.join("")
    }

    /// Generate Gnark expression for a node, with memoization based on ref count.
    ///
    /// This is the main code generation method. It:
    /// 1. Builds a post-order traversal (children before parents)
    /// 2. Generates Go expressions for each node
    /// 3. Hoists multi-referenced nodes to CSE variables
    /// 4. Returns the final expression for the root
    ///
    /// Uses iterative traversal to avoid stack overflow on deep ASTs.
    /// The Jolt verifier can produce ASTs with thousands of nodes in
    /// a single chain (e.g., sumcheck polynomial evaluations).
    pub(crate) fn generate_expr(&mut self, root_node_id: usize) -> String {
        // Phase 1: Build post-order traversal (children before parents)
        // We need to process nodes in an order where all children are processed before their parent
        let mut post_order: Vec<usize> = Vec::new();
        let mut visited: HashSet<usize> = HashSet::new();
        let mut stack: Vec<(usize, bool)> = vec![(root_node_id, false)];

        while let Some((node_id, children_processed)) = stack.pop() {
            if children_processed {
                // All children have been processed, add this node to post_order
                post_order.push(node_id);
                continue;
            }

            // Skip if already in post_order (already fully processed)
            if visited.contains(&node_id) {
                continue;
            }
            visited.insert(node_id);

            // Push this node back with children_processed = true
            stack.push((node_id, true));

            // Push unvisited children (reversed so left-to-right processing due to LIFO)
            for child_id in node_children(&self.nodes[node_id]).into_iter().rev() {
                if !visited.contains(&child_id) {
                    stack.push((child_id, false));
                }
            }
        }

        // Phase 2: Generate expressions in post-order (children before parents)
        for node_id in post_order {
            // Skip if already generated
            if self.generated.contains_key(&node_id) {
                continue;
            }

            let node = self.nodes[node_id].clone();

            // For atoms, just generate directly without hoisting
            if matches!(node, Node::Atom(_)) {
                // Don't store atoms in generated - they're always inlined
                continue;
            }

            // Generate the expression for this node (children are already in self.generated or are atoms)
            let expr = match node {
                // Atoms are skipped above, this arm is unreachable
                Node::Atom(_) => unreachable!("Atoms are skipped before this match"),

                // Binary arithmetic ops
                Node::Add(l, r) => self.binary_op("Add", l, r),
                Node::Mul(l, r) => self.binary_op("Mul", l, r),
                Node::Sub(l, r) => self.binary_op("Sub", l, r),

                // Unary ops
                Node::Inv(e) => self.unary_op("api.Inverse", e),
                Node::ByteReverse(e) => {
                    self.uses_poseidon = true;
                    self.unary_op("poseidon.ByteReverse", e)
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

                // Transcript hash (dispatched by hash_data variant)
                Node::TranscriptHash(ref hash_data, state, n_rounds) => {
                    let s = self.edge_to_gnark_iterative(state);
                    let r = self.edge_to_gnark_iterative(n_rounds);
                    match hash_data {
                        TranscriptHashData::Poseidon(data_edge) => {
                            self.uses_poseidon = true;
                            let d = self.edge_to_gnark_iterative(*data_edge);
                            format!("poseidon.Hash(api, {s}, {r}, {d})")
                        }
                        TranscriptHashData::Blake2b(_data_edges) => {
                            todo!("Blake2b Go codegen will be implemented in Phase 4")
                        }
                        TranscriptHashData::Keccak(_data_edges) => {
                            todo!("Keccak Go codegen will be implemented in Phase 4")
                        }
                    }
                }

                // zklean base nodes: Neg and Div are part of upstream zklean's Node enum.
                // Jolt's transpiler doesn't currently generate these (uses Sub(0,x) and Mul(a,Inv(b))),
                // but we support them for compatibility with Lean4 extraction paths.
                Node::Neg(e) => self.unary_op("api.Neg", e),
                Node::Div(e1, e2) => {
                    // gnark has no api.Div; implement as Mul(a, Inverse(b))
                    let a = self.edge_to_gnark_iterative(e1);
                    let b_inv = self.edge_to_gnark_iterative(e2);
                    format!("api.Mul({a}, api.Inverse({b_inv}))")
                }
            };

            // Hoist to CSE variable if referenced more than once OR expression is too large.
            // Large single-use expressions would create massive single-line Go code that
            // overwhelms the Go compiler (e.g., 48MB expression on one line).
            const MAX_INLINE_EXPR_LEN: usize = 1000;
            let ref_count = self.ref_counts.get(&node_id).copied().unwrap_or(1);
            if ref_count > 1 || expr.len() > MAX_INLINE_EXPR_LEN {
                let var_name = self.make_cse_name();
                self.cse_counter += 1;
                self.bindings.push(format!("\t{var_name} := {expr}\n"));
                self.generated.insert(node_id, var_name);
            } else {
                // Store the expression for single-use nodes too, so children can reference it
                self.generated.insert(node_id, expr);
            }
        }

        // Return the expression for the root node
        if let Some(expr) = self.generated.get(&root_node_id) {
            expr.clone()
        } else {
            // Root was an atom
            let node = self.nodes[root_node_id].clone();
            if let Node::Atom(atom) = node {
                self.atom_to_gnark(atom)
            } else {
                panic!("Root node {root_node_id} not found in generated expressions")
            }
        }
    }

    /// Generate a binary operation expression (api.Op(left, right))
    fn binary_op(&mut self, op: &str, left: Edge, right: Edge) -> String {
        let l = self.edge_to_gnark_iterative(left);
        let r = self.edge_to_gnark_iterative(right);
        format!("api.{op}({l}, {r})")
    }

    /// Generate a unary operation expression (func(api, arg))
    fn unary_op(&mut self, func: &str, arg: Edge) -> String {
        let a = self.edge_to_gnark_iterative(arg);
        // api.Inverse doesn't take api as first arg, poseidon helpers do
        if func.starts_with("api.") {
            format!("{func}({a})")
        } else {
            format!("{func}(api, {a})")
        }
    }

    // -------------------------------------------------------------------------
    // Private helper methods
    // -------------------------------------------------------------------------

    /// Generate a CSE variable name using the configured prefix
    fn make_cse_name(&self) -> String {
        let constraint_idx = self.constraint_idx;
        let cse_counter = self.cse_counter;
        format!("cse_{constraint_idx}_{cse_counter}")
    }

    /// Generate Gnark expression for an atom
    fn atom_to_gnark(&mut self, atom: Atom) -> String {
        match atom {
            Atom::Scalar(value) => format_scalar_for_gnark(value),
            Atom::Var(index) => self
                .var_names
                .get(&index)
                .map(|name| format!("circuit.{}", sanitize_go_name(name)))
                .unwrap_or_else(|| format!("circuit.X_{index}")),
            Atom::NamedVar(index) => {
                let constraint_idx = self.constraint_idx;
                format!("cse_{constraint_idx}_{index}")
            }
        }
    }

    /// Non-recursive edge_to_gnark that looks up already-generated expressions
    fn edge_to_gnark_iterative(&mut self, edge: Edge) -> String {
        match edge {
            Edge::Atom(atom) => self.atom_to_gnark(atom),
            Edge::NodeRef(node_id) => {
                // Child should already be generated (we're in post-order), or it's an atom
                self.generated
                    .get(&node_id)
                    .cloned()
                    .unwrap_or_else(|| match self.nodes[node_id] {
                        Node::Atom(atom) => self.atom_to_gnark(atom),
                        _ => panic!("Node {node_id} not in generated - post-order traversal bug"),
                    })
            }
        }
    }
}

// =============================================================================
// Public functions
// =============================================================================

/// Generate a complete Gnark circuit from an AstBundle.
///
/// Wrapper around [`generate_circuit_from_bundle_with_stats`] that panics on
/// static verification failures.
///
/// # Panics
///
/// Panics if any constant assertion evaluates to non-zero (static verification failure).
///
/// # Panics
///
/// Also panics if the bundle contains any Fq variables, as Fq codegen is not yet implemented.
pub fn generate_circuit_from_bundle(
    bundle: &zklean_extractor::mle_ast::AstBundle,
    circuit_name: &str,
) -> String {
    // Early check for unsupported non-native field arithmetic
    if bundle.has_inputs_for_field(TargetField::Fq) {
        let non_native_vars: Vec<_> = bundle
            .inputs
            .iter()
            .filter(|i| i.target_field.is_non_native())
            .map(|i| (&i.name, i.target_field))
            .take(10) // Limit output
            .collect();
        panic!(
            "Non-native field codegen not yet implemented.\n\
             Bundle contains {} non-native variable(s), first 10: {:?}\n\
             For non-native field support design, see: guides/fq-aware-transpilation-design.md",
            bundle
                .inputs
                .iter()
                .filter(|i| i.target_field.is_non_native())
                .count(),
            non_native_vars
        );
    }

    let (code, stats) = generate_circuit_from_bundle_with_stats(bundle, circuit_name);

    // Log statistics
    if stats.constant_skipped > 0 || stats.constant_failed > 0 {
        eprintln!(
            "Codegen stats: {} total constraints, {} constant-skipped, {} constant-failed",
            stats.total_constraints, stats.constant_skipped, stats.constant_failed
        );
    }

    // Panic if any constant assertions failed
    if stats.constant_failed > 0 {
        panic!(
            "Static verification failed: {} constant assertions are non-zero: {:?}",
            stats.constant_failed, stats.failed_names
        );
    }

    code
}

/// Generate a complete Gnark circuit from an AstBundle, returning statistics.
///
/// This is the core codegen function. Unlike [`generate_circuit_from_bundle`], it does
/// not panic on failures. Instead it records them in the returned statistics.
///
/// # Constant Assertion Handling
///
/// If a constraint expression is entirely constant (contains no variables):
/// - **EqualZero + constant == 0**: Constraint is skipped (statically satisfied)
/// - **EqualZero + constant != 0**: Failure recorded in `stats.constant_failed`,
///   constraint still emitted (will fail at prove time)
/// - **Other assertion types**: Emitted normally (no static verification)
///
/// Callers should check `stats.constant_failed > 0` to detect static failures.
///
/// # Per-Constraint Expression Trees
///
/// Each constraint gets isolated CSE namespacing (`cse_0_*`, `cse_1_*`, etc.).
/// This makes debugging easier: when a constraint fails, all its CSE variables
/// are self-contained.
pub fn generate_circuit_from_bundle_with_stats(
    bundle: &zklean_extractor::mle_ast::AstBundle,
    circuit_name: &str,
) -> (String, ConstantAssertionStats) {
    use zklean_extractor::mle_ast::{Assertion, WitnessType};

    let mut stats = ConstantAssertionStats::default();

    // Validate circuit name: must be a valid Go identifier
    let circuit_name = sanitize_go_name(circuit_name);

    // Build var_names mapping from bundle inputs
    let var_names: HashMap<u16, String> = bundle
        .inputs
        .iter()
        .map(|input| (input.index, input.name.clone()))
        .collect();

    // Process each constraint with its own CSE context.
    // This makes debugging easier: each constraint's cse_N_* variables are isolated.
    let mut processed_constraints: Vec<ProcessedConstraint> = Vec::new();

    // Require pre-computed CSE bindings
    if !bundle.has_cse() {
        panic!(
            "AstBundle must have pre-computed CSE bindings. Call bundle.run_cse() before codegen."
        );
    }

    for (constraint_idx, c) in bundle.constraints.iter().enumerate() {
        // Use pre-computed CSE bindings from AstBundle
        let cse_bindings = bundle.get_cse_bindings(constraint_idx).unwrap_or(&[]);
        let mut codegen =
            GnarkCodeGen::new(&bundle.nodes, &var_names, constraint_idx, cse_bindings);

        // Generate expression for this constraint
        let expr = codegen.generate_expr(c.root);

        // Build the assertion (converting to owned form and generating other_expr if needed)
        let assertion = match &c.assertion {
            Assertion::EqualZero => ConstraintAssertion::EqualZero,
            Assertion::EqualPublicInput { name } => {
                ConstraintAssertion::EqualPublicInput { name: name.clone() }
            }
            Assertion::EqualNode(other_id) => {
                let other_expr = codegen.generate_expr(*other_id);
                ConstraintAssertion::EqualNode { other_expr }
            }
        };

        // Check if constant and evaluate
        let is_const = is_node_constant_in(&bundle.nodes, c.root);
        let const_val = if is_const {
            Some(evaluate_constant_node_in(&bundle.nodes, c.root))
        } else {
            None
        };

        // Track poseidon usage
        if codegen.uses_poseidon() {
            stats.uses_poseidon = true;
        }

        // Get bindings (will be empty string if none)
        let bindings = if codegen.bindings_code().is_empty() {
            String::new()
        } else {
            format!(
                "\t// CSE bindings for constraint {constraint_idx}\n{}",
                codegen.bindings_code()
            )
        };

        processed_constraints.push(ProcessedConstraint {
            name: c.name.clone(),
            expr,
            bindings,
            assertion,
            is_const,
            const_val,
        });
    }

    stats.total_constraints = processed_constraints.len();

    // Generate G1 curve operation code (if any)
    let g1_result = generate_g1_code(
        &bundle.g1_ops,
        &bundle.g1_constraints,
        &bundle.nodes,
        &var_names,
        &circuit_name,
    );

    // Collect all struct field names with their target field types
    // Using BTreeMap to deduplicate by name while preserving field type
    let mut struct_fields: BTreeMap<String, TargetField> = BTreeMap::new();

    for input in &bundle.inputs {
        if input.witness_type == WitnessType::ProofData
            || input.witness_type == WitnessType::PublicStatement
        {
            struct_fields.insert(sanitize_go_name(&input.name), input.target_field);
        }
    }
    for constraint in &bundle.constraints {
        if let Assertion::EqualPublicInput { name } = &constraint.assertion {
            // Public inputs from constraints default to Fr (native field)
            struct_fields
                .entry(sanitize_go_name(name))
                .or_insert(TargetField::Fr);
        }
    }
    // Add G1 witness variable fields (X, Y coordinates as native Fr)
    for field_name in &g1_result.struct_fields {
        struct_fields
            .entry(field_name.clone())
            .or_insert(TargetField::Fr);
    }

    // Build output
    let mut output = String::new();

    // Package and imports
    output.push_str("package jolt_verifier\n\n");
    output.push_str("import (\n");
    output.push_str("\t\"math/big\"\n");
    output.push('\n');
    output.push_str("\t\"github.com/consensys/gnark/frontend\"\n");
    if g1_result.needs_sw_grumpkin {
        output.push_str(
            "\t\"github.com/consensys/gnark/std/algebra/native/sw_grumpkin\"\n",
        );
    }
    if g1_result.needs_emulated {
        output.push_str("\t\"github.com/consensys/gnark/std/math/emulated\"\n");
    }
    if stats.uses_poseidon {
        output.push_str("\t\"jolt_verifier/poseidon\"\n");
    }
    output.push_str(")\n\n");

    // bigInt helper for large constants that overflow Go's int64
    output.push_str(
        "// bigInt creates a *big.Int from a string, for constants too large for int64\n",
    );
    output.push_str("func bigInt(s string) *big.Int {\n");
    output.push_str("\tn, ok := new(big.Int).SetString(s, 10)\n");
    output.push_str("\tif !ok {\n");
    output.push_str("\t\tpanic(\"invalid bigInt: \" + s)\n");
    output.push_str("\t}\n");
    output.push_str("\treturn n\n");
    output.push_str("}\n\n");

    // Circuit struct - deduplicated fields with correct types based on TargetField
    output.push_str(&format!("type {circuit_name} struct {{\n"));
    for (field_name, target_field) in &struct_fields {
        let go_type = match target_field {
            TargetField::Fr => "frontend.Variable",
            TargetField::Fq => {
                // Fq would use emulated arithmetic: emulated.Element[emulated.BN254Fp]
                // But Fq codegen is not implemented, so this is unreachable due to the
                // early panic in generate_circuit_from_bundle(). We include this branch
                // for completeness and future reference.
                "emulated.Element[emulated.BN254Fp]"
            }
        };
        output.push_str(&format!("\t{field_name} {go_type} `gnark:\",public\"`\n"));
    }
    output.push_str("}\n\n");

    // Emit per-constraint helper methods.
    // Each constraint gets its own function to avoid arm64 "branch too far" compiler
    // errors when the entire circuit is in a single Define() method.
    // Large constraints are further split into sub-functions (max ~2000 binding lines each).
    const MAX_BINDING_LINES: usize = 2000;
    let mut constraint_func_names: Vec<String> = Vec::new();

    for (idx, pc) in processed_constraints.iter().enumerate() {
        // Static verification for constant EqualZero assertions
        if pc.is_const && matches!(&pc.assertion, ConstraintAssertion::EqualZero) {
            let val = pc.const_val.unwrap_or([0, 0, 0, 0]);
            if val == [0, 0, 0, 0] {
                // Constant equals zero - statically satisfied, skip entirely
                output.push_str(&format!(
                    "// {} = 0 (statically verified, skipped)\n\n",
                    pc.name
                ));
                stats.constant_skipped += 1;
                continue;
            } else {
                // Constant != 0 - static failure, emit warning comment but still generate constraint
                output.push_str(&format!("// {} STATIC FAILURE: constant != 0\n", pc.name));
                stats.constant_failed += 1;
                stats.failed_names.push(pc.name.clone());
            }
        }

        let func_name = format!("verifyConstraint{idx}");
        constraint_func_names.push(func_name.clone());

        // Count binding lines to decide if we need sub-function splitting
        let binding_lines: Vec<&str> = if pc.bindings.is_empty() {
            Vec::new()
        } else {
            pc.bindings.lines().filter(|l| !l.is_empty()).collect()
        };

        let needs_splitting = binding_lines.len() > MAX_BINDING_LINES;
        let var_name = sanitize_go_name(&pc.name);

        if needs_splitting {
            // Split bindings into sub-functions that share state via a slice.
            // CSE bindings reference each other by name (cse_K_N). We rewrite them
            // to use a slice (cse[N]) so sub-functions can share intermediate values.
            let num_bindings = binding_lines.len();
            let num_parts = num_bindings.div_ceil(MAX_BINDING_LINES);

            // Emit sub-functions for binding batches
            for part in 0..num_parts {
                let start = part * MAX_BINDING_LINES;
                let end = std::cmp::min(start + MAX_BINDING_LINES, num_bindings);

                output.push_str(&format!(
                    "func (circuit *{circuit_name}) {func_name}Bindings{part}(api frontend.API, cse []frontend.Variable) {{\n"
                ));

                for line in &binding_lines[start..end] {
                    // Rewrite "cse_K_N := expr" to "cse[N] = expr" and
                    // references to "cse_K_M" to "cse[M]" within the expression
                    let rewritten = rewrite_cse_to_slice(line, idx);
                    output.push_str(&rewritten);
                    output.push('\n');
                }

                output.push_str("}\n\n");
            }

            // Emit the main constraint function that calls sub-functions
            output.push_str(&format!("// {func_name} verifies: {}\n", pc.name));
            output.push_str(&format!(
                "func (circuit *{circuit_name}) {func_name}(api frontend.API) {{\n"
            ));
            output.push_str(&format!(
                "\tcse := make([]frontend.Variable, {num_bindings})\n"
            ));

            for part in 0..num_parts {
                output.push_str(&format!("\tcircuit.{func_name}Bindings{part}(api, cse)\n"));
            }

            // Rewrite the final expression to use cse[N] references
            let rewritten_expr = rewrite_cse_refs_to_slice(&pc.expr, idx);
            output.push_str(&format!("\t{var_name} := {rewritten_expr}\n"));
        } else {
            // Small constraint: emit as a single function with named CSE variables
            output.push_str(&format!("// {func_name} verifies: {}\n", pc.name));
            output.push_str(&format!(
                "func (circuit *{circuit_name}) {func_name}(api frontend.API) {{\n"
            ));

            if !pc.bindings.is_empty() {
                output.push_str(&pc.bindings);
            }

            output.push_str(&format!("\t{var_name} := {}\n", pc.expr));
        }

        // Emit assertion
        match &pc.assertion {
            ConstraintAssertion::EqualZero => {
                output.push_str(&format!("\tapi.AssertIsEqual({var_name}, 0)\n"));
            }
            ConstraintAssertion::EqualPublicInput { name: pub_name } => {
                output.push_str(&format!(
                    "\tapi.AssertIsEqual({var_name}, circuit.{})\n",
                    sanitize_go_name(pub_name)
                ));
            }
            ConstraintAssertion::EqualNode { other_expr } => {
                let rewritten = if needs_splitting {
                    rewrite_cse_refs_to_slice(other_expr, idx)
                } else {
                    other_expr.clone()
                };
                output.push_str(&format!("\tapi.AssertIsEqual({var_name}, {rewritten})\n"));
            }
        }

        output.push_str("}\n\n");
    }

    // G1 curve operations method (if any)
    if !g1_result.method_code.is_empty() {
        output.push_str(&g1_result.method_code);
    }

    // Define method: calls each per-constraint helper and G1 ops
    output.push_str(&format!(
        "func (circuit *{circuit_name}) Define(api frontend.API) error {{\n"
    ));

    for func_name in &constraint_func_names {
        output.push_str(&format!("\tcircuit.{func_name}(api)\n"));
    }

    if !g1_result.method_code.is_empty() {
        output.push_str("\tif err := circuit.verifyG1Ops(api); err != nil {\n");
        output.push_str("\t\treturn err\n");
        output.push_str("\t}\n");
    }

    output.push_str("\treturn nil\n");
    output.push_str("}\n");

    (output, stats)
}

/// Rewrite a CSE binding line from named variables to slice indexing.
///
/// Converts `\tcse_18_42 := api.Add(cse_18_3, circuit.X)` to
/// `\tcse[42] = api.Add(cse[3], circuit.X)`.
fn rewrite_cse_to_slice(line: &str, constraint_idx: usize) -> String {
    let prefix = format!("cse_{constraint_idx}_");
    let mut result = String::with_capacity(line.len());
    let mut i = 0;
    let bytes = line.as_bytes();

    while i < bytes.len() {
        if line[i..].starts_with(&prefix) {
            // Found a cse reference, extract the number
            let num_start = i + prefix.len();
            let mut num_end = num_start;
            while num_end < bytes.len() && bytes[num_end].is_ascii_digit() {
                num_end += 1;
            }
            let num = &line[num_start..num_end];
            result.push_str(&format!("cse[{num}]"));
            i = num_end;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    // Replace first `:=` with `=` (slice assignment, not declaration)
    result.replacen(":=", "=", 1)
}

/// Rewrite CSE references in an expression from named variables to slice indexing.
///
/// Converts `cse_18_42` to `cse[42]` in expression strings.
fn rewrite_cse_refs_to_slice(expr: &str, constraint_idx: usize) -> String {
    let prefix = format!("cse_{constraint_idx}_");
    let mut result = String::with_capacity(expr.len());
    let mut i = 0;
    let bytes = expr.as_bytes();

    while i < bytes.len() {
        if expr[i..].starts_with(&prefix) {
            let num_start = i + prefix.len();
            let mut num_end = num_start;
            while num_end < bytes.len() && bytes[num_end].is_ascii_digit() {
                num_end += 1;
            }
            let num = &expr[num_start..num_end];
            result.push_str(&format!("cse[{num}]"));
            i = num_end;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Sanitize a name for use as a Go identifier (PascalCase with underscores).
///
/// Converts any input string to Go-compatible identifier:
/// - `"foo_bar_baz"` → `"Foo_Bar_Baz"` (underscores preserved)
/// - `"stage1.sumcheck[0]"` → `"Stage1_Sumcheck_0"`
/// - `"UPPER_CASE"` → `"UPPER_CASE"` (case preserved)
/// - `"JoltStagesCircuit"` → `"JoltStagesCircuit"` (preserved)
///
/// IMPORTANT: Underscores are preserved to maintain consistency between:
/// - VarAllocator descriptions (e.g., "stage1_sumcheck_r0_0")
/// - Circuit struct field names (e.g., "Stage1_Sumcheck_R0_0")
/// - Witness JSON keys (e.g., "Stage1_Sumcheck_R0_0")
pub fn sanitize_go_name(name: &str) -> String {
    // Replace any non-alphanumeric character with underscore
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();

    // Split by underscores and PascalCase each segment, preserving underscores between parts
    cleaned
        .split('_')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    // Capitalize first char, preserve the rest (for CamelCase names)
                    first.to_uppercase().chain(chars).collect()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("_")
}

// =============================================================================
// Private helper functions
// =============================================================================

/// Format a scalar value ([u64; 4]) for Gnark code generation.
///
/// Small values that fit in Go's int64 are emitted as literals (e.g., `42`).
/// Large values are formatted as `bigInt("...")` calls.
///
/// Note: gnark's API accepts both int and *big.Int, so using bigInt for everything
/// would also work. We use int literals for small values because it produces
/// more readable output and slightly smaller generated files.
fn format_scalar_for_gnark(limbs: [u64; 4]) -> String {
    // Check if it fits in i64 (only limb[0] is non-zero and within range)
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        let value = limbs[0];
        if value <= i64::MAX as u64 {
            return format!("{value}");
        }
    }

    // Too large for int64, use bigInt helper
    use num_bigint::BigUint;

    let mut value = BigUint::from(limbs[3]);
    value = (value << 64) + limbs[2];
    value = (value << 64) + limbs[1];
    value = (value << 64) + limbs[0];

    format!("bigInt(\"{value}\")")
}

/// Check if a node is constant (contains no variables), reading from a node slice.
fn is_node_constant_in(nodes: &[Node], node_id: usize) -> bool {
    match nodes[node_id] {
        Node::Atom(Atom::Scalar(_)) => true,
        Node::Atom(Atom::Var(_)) => false,
        Node::Atom(Atom::NamedVar(_)) => false,
        Node::Neg(e)
        | Node::Inv(e)
        | Node::ByteReverse(e)
        | Node::Truncate128Reverse(e)
        | Node::Truncate128(e)
        | Node::AppendU64Transform(e) => is_edge_constant_in(nodes, e),
        Node::Add(e1, e2) | Node::Mul(e1, e2) | Node::Sub(e1, e2) | Node::Div(e1, e2) => {
            is_edge_constant_in(nodes, e1) && is_edge_constant_in(nodes, e2)
        }
        Node::TranscriptHash(ref hash_data, e1, e2) => {
            is_edge_constant_in(nodes, e1)
                && is_edge_constant_in(nodes, e2)
                && hash_data
                    .as_slice()
                    .iter()
                    .all(|e| is_edge_constant_in(nodes, *e))
        }
    }
}

fn is_edge_constant_in(nodes: &[Node], edge: Edge) -> bool {
    match edge {
        Edge::Atom(Atom::Scalar(_)) => true,
        Edge::Atom(Atom::Var(_)) => false,
        Edge::Atom(Atom::NamedVar(_)) => false,
        Edge::NodeRef(id) => is_node_constant_in(nodes, id),
    }
}

/// Evaluate a constant node to its scalar value, reading from a node slice.
fn evaluate_constant_node_in(nodes: &[Node], node_id: usize) -> Scalar {
    match nodes[node_id] {
        Node::Atom(Atom::Scalar(s)) => s,
        Node::Atom(Atom::Var(_)) | Node::Atom(Atom::NamedVar(_)) => {
            panic!("Cannot evaluate non-constant node")
        }
        Node::Add(e1, e2) => scalar_add_mod(
            evaluate_constant_edge_in(nodes, e1),
            evaluate_constant_edge_in(nodes, e2),
        ),
        Node::Sub(e1, e2) => scalar_sub_mod(
            evaluate_constant_edge_in(nodes, e1),
            evaluate_constant_edge_in(nodes, e2),
        ),
        Node::Mul(e1, e2) => scalar_mul_mod(
            evaluate_constant_edge_in(nodes, e1),
            evaluate_constant_edge_in(nodes, e2),
        ),
        Node::Neg(e) => scalar_neg_mod(evaluate_constant_edge_in(nodes, e)),
        Node::Inv(_) | Node::Div(_, _) => {
            panic!("Modular inverse not implemented for constant evaluation")
        }
        Node::TranscriptHash(_, _, _)
        | Node::ByteReverse(_)
        | Node::Truncate128Reverse(_)
        | Node::Truncate128(_)
        | Node::AppendU64Transform(_) => {
            panic!("Hash/transform operations cannot be evaluated as constants")
        }
    }
}

fn evaluate_constant_edge_in(nodes: &[Node], edge: Edge) -> Scalar {
    match edge {
        Edge::Atom(Atom::Scalar(s)) => s,
        Edge::Atom(Atom::Var(_)) | Edge::Atom(Atom::NamedVar(_)) => {
            panic!("Cannot evaluate non-constant edge")
        }
        Edge::NodeRef(id) => evaluate_constant_node_in(nodes, id),
    }
}

// =============================================================================
// G1 Curve Operation Codegen (sw_grumpkin)
// =============================================================================

/// CSE constraint index used for scalar expressions referenced by G1 operations.
/// Uses a high index to avoid collisions with field constraint indices.
const G1_SCALAR_CSE_IDX: usize = usize::MAX / 2;

/// Result of G1 code generation.
struct G1CodeGenResult {
    /// Struct field names for G1 witness variables (X and Y coordinates).
    /// Each entry is a field name (e.g., "Bf_Round_Commit_0_X").
    struct_fields: Vec<String>,
    /// Go code for the `verifyG1Ops` method body.
    method_code: String,
    /// Whether the generated code needs the `sw_grumpkin` import.
    needs_sw_grumpkin: bool,
    /// Whether the generated code needs the `emulated` import.
    needs_emulated: bool,
}

/// Generate gnark Go code for G1 curve operations from the G1 operation arena.
///
/// Traverses the G1 operation arena and emits `sw_grumpkin` gnark API calls:
/// - `G1Op::Var(name)` → struct fields `{Name}_X, {Name}_Y` + point construction
/// - `G1Op::Add(a, b)` → `curve.Add(g1_a, g1_b)`
/// - `G1Op::ScalarMul(p, s)` → bit decomposition + `curve.ScalarMul(g1_p, scalar)`
/// - `G1Op::MSM(bases, scalars)` → `curve.MultiScalarMul(bases, scalars)`
/// - G1 constraints → `curve.AssertIsEqual(g1_a, g1_b)`
///
/// Scalars referenced by ScalarMul/MSM are BN254 Fr (native circuit field) but
/// Grumpkin expects scalars in its scalar field (= BN254 Fq). Since Fr < Fq,
/// we convert via bit decomposition: `api.ToBinary(scalar, 254)` →
/// `scalarField.FromBits(bits...)`.
fn generate_g1_code(
    g1_ops: &[G1Op],
    g1_constraints: &[G1Constraint],
    nodes: &[Node],
    var_names: &HashMap<u16, String>,
    circuit_name: &str,
) -> G1CodeGenResult {
    if g1_ops.is_empty() && g1_constraints.is_empty() {
        return G1CodeGenResult {
            struct_fields: Vec::new(),
            method_code: String::new(),
            needs_sw_grumpkin: false,
            needs_emulated: false,
        };
    }

    let mut struct_fields = Vec::new();
    let mut body = String::new();

    let has_scalar_ops = g1_ops
        .iter()
        .any(|op| matches!(op, G1Op::ScalarMul(_, _) | G1Op::MSM(_, _)));
    let has_arithmetic = g1_ops.iter().any(|op| !matches!(op, G1Op::Var(_)));
    let has_constraints = !g1_constraints.is_empty();

    // Only emit the verifyG1Ops method if there are actual operations or constraints
    if !has_arithmetic && !has_constraints {
        // Only Var ops — just collect struct fields, no method needed
        for op in g1_ops {
            if let G1Op::Var(name) = op {
                let go_name = sanitize_go_name(name);
                struct_fields.push(format!("{go_name}_X"));
                struct_fields.push(format!("{go_name}_Y"));
            }
        }
        return G1CodeGenResult {
            struct_fields,
            method_code: String::new(),
            needs_sw_grumpkin: false,
            needs_emulated: false,
        };
    }

    // Build the verifyG1Ops method
    body.push_str(&format!(
        "// verifyG1Ops verifies G1 curve operation constraints (Grumpkin native)\n"
    ));
    body.push_str(&format!(
        "func (circuit *{circuit_name}) verifyG1Ops(api frontend.API) error {{\n"
    ));

    // Initialize curve
    body.push_str("\tcurve, err := sw_grumpkin.NewCurve(api)\n");
    body.push_str("\tif err != nil {\n");
    body.push_str("\t\treturn err\n");
    body.push_str("\t}\n");

    if has_scalar_ops {
        body.push_str(
            "\tscalarField, err := emulated.NewField[sw_grumpkin.ScalarField](api)\n",
        );
        body.push_str("\tif err != nil {\n");
        body.push_str("\t\treturn err\n");
        body.push_str("\t}\n");
    }
    body.push('\n');

    // Pre-compute all scalar expressions referenced by G1 ops using a SINGLE
    // GnarkCodeGen instance. This ensures CSE bindings are shared across all
    // scalar expressions and defined once before any references.
    let mut scalar_exprs: HashMap<usize, String> = HashMap::new();
    if has_scalar_ops {
        let mut scalar_node_ids: Vec<usize> = Vec::new();
        for op in g1_ops.iter() {
            match op {
                G1Op::ScalarMul(_, scalar_id) => {
                    if !scalar_node_ids.contains(scalar_id) {
                        scalar_node_ids.push(*scalar_id);
                    }
                }
                G1Op::MSM(_, scalars) => {
                    for s in scalars {
                        if !scalar_node_ids.contains(s) {
                            scalar_node_ids.push(*s);
                        }
                    }
                }
                _ => {}
            }
        }

        let mut codegen =
            GnarkCodeGen::new(nodes, var_names, G1_SCALAR_CSE_IDX, &[]);
        for &node_id in &scalar_node_ids {
            let expr = match &nodes[node_id] {
                Node::Atom(Atom::Var(idx)) => var_names
                    .get(idx)
                    .map(|name| format!("circuit.{}", sanitize_go_name(name)))
                    .unwrap_or_else(|| format!("circuit.X_{idx}")),
                Node::Atom(Atom::Scalar(s)) => format_scalar_for_gnark(*s),
                _ => codegen.generate_expr(node_id),
            };
            scalar_exprs.insert(node_id, expr);
        }

        let bindings = codegen.bindings_code();
        if !bindings.is_empty() {
            body.push_str("\t// CSE bindings for G1 scalar expressions\n");
            body.push_str(&bindings);
            body.push('\n');
        }
    }

    // Generate code for each G1 operation
    for (idx, op) in g1_ops.iter().enumerate() {
        match op {
            G1Op::Var(name) => {
                let go_name = sanitize_go_name(name);
                struct_fields.push(format!("{go_name}_X"));
                struct_fields.push(format!("{go_name}_Y"));
                body.push_str(&format!(
                    "\tg1_{idx} := &sw_grumpkin.G1Affine{{X: circuit.{go_name}_X, Y: circuit.{go_name}_Y}}\n"
                ));
            }
            G1Op::Zero => {
                body.push_str(&format!(
                    "\tg1_{idx} := &sw_grumpkin.G1Affine{{X: 0, Y: 0}} // identity\n"
                ));
            }
            G1Op::Add(a, b) => {
                body.push_str(&format!("\tg1_{idx} := curve.Add(g1_{a}, g1_{b})\n"));
            }
            G1Op::Sub(a, b) => {
                body.push_str(&format!("\tg1_{idx}_neg := curve.Neg(g1_{b})\n"));
                body.push_str(&format!(
                    "\tg1_{idx} := curve.Add(g1_{a}, g1_{idx}_neg)\n"
                ));
            }
            G1Op::Neg(a) => {
                body.push_str(&format!("\tg1_{idx} := curve.Neg(g1_{a})\n"));
            }
            G1Op::Double(a) => {
                body.push_str(&format!("\tg1_{idx} := curve.Add(g1_{a}, g1_{a})\n"));
            }
            G1Op::ScalarMul(point_id, scalar_node_id) => {
                let scalar_expr = &scalar_exprs[scalar_node_id];
                body.push_str(&format!(
                    "\tg1_{idx}_bits := api.ToBinary({scalar_expr}, 254)\n"
                ));
                body.push_str(&format!(
                    "\tg1_{idx}_s := scalarField.FromBits(g1_{idx}_bits...)\n"
                ));
                body.push_str(&format!(
                    "\tg1_{idx} := curve.ScalarMul(g1_{point_id}, g1_{idx}_s)\n"
                ));
            }
            G1Op::MSM(bases, scalars) => {
                let n = bases.len();
                body.push_str(&format!(
                    "\tg1_{idx}_bases := make([]*sw_grumpkin.G1Affine, {n})\n"
                ));
                body.push_str(&format!(
                    "\tg1_{idx}_scalars := make([]*sw_grumpkin.Scalar, {n})\n"
                ));
                for (i, base_id) in bases.iter().enumerate() {
                    body.push_str(&format!(
                        "\tg1_{idx}_bases[{i}] = g1_{base_id}\n"
                    ));
                }
                for (i, scalar_node_id) in scalars.iter().enumerate() {
                    let scalar_expr = &scalar_exprs[scalar_node_id];
                    body.push_str(&format!(
                        "\tg1_{idx}_s{i}_bits := api.ToBinary({scalar_expr}, 254)\n"
                    ));
                    body.push_str(&format!(
                        "\tg1_{idx}_s{i} := scalarField.FromBits(g1_{idx}_s{i}_bits...)\n"
                    ));
                    body.push_str(&format!(
                        "\tg1_{idx}_scalars[{i}] = g1_{idx}_s{i}\n"
                    ));
                }
                body.push_str(&format!(
                    "\tg1_{idx}, err := curve.MultiScalarMul(g1_{idx}_bases, g1_{idx}_scalars)\n"
                ));
                body.push_str("\tif err != nil {\n");
                body.push_str("\t\treturn err\n");
                body.push_str("\t}\n");
            }
        }
    }

    // G1 equality constraints
    if !g1_constraints.is_empty() {
        body.push_str("\n\t// G1 equality constraints\n");
        for c in g1_constraints {
            body.push_str(&format!(
                "\tcurve.AssertIsEqual(g1_{}, g1_{}) // {}\n",
                c.lhs, c.rhs, c.name
            ));
        }
    }

    // Suppress unused G1 variable warnings.
    // Collect which g1_idx values are referenced by later ops or constraints.
    let mut referenced: HashSet<usize> = HashSet::new();
    for op in g1_ops.iter() {
        match op {
            G1Op::Add(a, b) | G1Op::Sub(a, b) => {
                referenced.insert(*a as usize);
                referenced.insert(*b as usize);
            }
            G1Op::Neg(a) | G1Op::Double(a) => {
                referenced.insert(*a as usize);
            }
            G1Op::ScalarMul(p, _) => {
                referenced.insert(*p as usize);
            }
            G1Op::MSM(bases, _) => {
                for b in bases {
                    referenced.insert(*b as usize);
                }
            }
            _ => {}
        }
    }
    for c in g1_constraints.iter() {
        referenced.insert(c.lhs as usize);
        referenced.insert(c.rhs as usize);
    }
    for idx in 0..g1_ops.len() {
        if !referenced.contains(&idx) {
            body.push_str(&format!("\t_ = g1_{idx}\n"));
        }
    }

    body.push_str("\t_ = curve\n");
    if has_scalar_ops {
        body.push_str("\t_ = scalarField\n");
    }

    body.push_str("\treturn nil\n");
    body.push_str("}\n\n");

    G1CodeGenResult {
        struct_fields,
        method_code: body,
        needs_sw_grumpkin: true,
        needs_emulated: has_scalar_ops,
    }
}

// scalar_node_to_gnark was removed — G1 scalar expressions are now pre-computed
// in generate_g1_code() using a single shared GnarkCodeGen instance, which
// ensures CSE bindings are defined before any references.

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zklean_extractor::mle_ast::{AstBundle, TargetField, WitnessType};

    /// Verifies that codegen panics with a clear error when non-native field variables are present.
    ///
    /// This test ensures `target_field` is actually being read and interpreted by codegen,
    /// not just stored and ignored.
    #[test]
    #[should_panic(expected = "Non-native field codegen not yet implemented")]
    fn test_non_native_field_variable_panics_in_codegen() {
        let mut bundle = AstBundle::new();

        // Add an Fr variable (should be fine)
        bundle.add_input_with_field(0, "fr_var", WitnessType::ProofData, TargetField::Fr);

        // Add a non-native field variable (Fq in this case, but could be any non-Fr field)
        bundle.add_input_with_field(1, "non_native_var", WitnessType::ProofData, TargetField::Fq);

        // This should panic because non-native field codegen is not implemented
        let _ = generate_circuit_from_bundle(&bundle, "TestCircuit");
    }

    /// Verifies the panic message includes the non-native variable name and field type.
    #[test]
    fn test_non_native_panic_message_includes_variable_name() {
        let mut bundle = AstBundle::new();
        bundle.add_input_with_field(
            0,
            "my_non_native_test_variable",
            WitnessType::ProofData,
            TargetField::Fq,
        );

        let result =
            std::panic::catch_unwind(|| generate_circuit_from_bundle(&bundle, "TestCircuit"));

        let panic_msg = result
            .expect_err("Expected panic for non-native field variable")
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();

        assert!(
            panic_msg.contains("my_non_native_test_variable"),
            "Panic message should include the variable name, got: {panic_msg}"
        );
        assert!(
            panic_msg.contains("Fq"),
            "Panic message should mention the field type, got: {panic_msg}"
        );
    }

    // =========================================================================
    // sanitize_go_name tests
    // =========================================================================
    // These tests are CRITICAL because sanitize_go_name must produce identical
    // output for circuit struct fields and witness JSON keys. Any mismatch
    // causes witness loading to fail silently with all-zero values.

    #[test]
    fn test_sanitize_go_name_underscore_preservation() {
        // Underscores must be preserved to maintain field structure
        assert_eq!(sanitize_go_name("stage1_sumcheck_r0"), "Stage1_Sumcheck_R0");
        assert_eq!(sanitize_go_name("my_var_name"), "My_Var_Name");
        assert_eq!(sanitize_go_name("a_b_c"), "A_B_C");
    }

    #[test]
    fn test_sanitize_go_name_bracket_replacement() {
        // Brackets and other special chars become underscores
        assert_eq!(
            sanitize_go_name("compressed_polys[0]"),
            "Compressed_Polys_0"
        );
        assert_eq!(sanitize_go_name("point(x,y)"), "Point_X_Y");
        assert_eq!(sanitize_go_name("foo-bar"), "Foo_Bar");
    }

    #[test]
    fn test_sanitize_go_name_preserves_case_after_first() {
        // First char of each segment capitalized, rest preserved (CamelCase support)
        assert_eq!(sanitize_go_name("myVar"), "MyVar");
        assert_eq!(sanitize_go_name("myVarName"), "MyVarName");
        assert_eq!(sanitize_go_name("XMLParser"), "XMLParser");
    }

    #[test]
    fn test_sanitize_go_name_empty_segments_filtered() {
        // Multiple consecutive underscores should not create empty segments
        assert_eq!(sanitize_go_name("a__b"), "A_B");
        assert_eq!(sanitize_go_name("foo___bar"), "Foo_Bar");
        assert_eq!(sanitize_go_name("_leading"), "Leading");
        assert_eq!(sanitize_go_name("trailing_"), "Trailing");
    }

    #[test]
    fn test_sanitize_go_name_numeric_suffixes() {
        // Numbers should work correctly in variable names
        assert_eq!(sanitize_go_name("r0"), "R0");
        assert_eq!(sanitize_go_name("stage1"), "Stage1");
        assert_eq!(sanitize_go_name("var_123"), "Var_123");
        assert_eq!(sanitize_go_name("123abc"), "123abc");
    }

    #[test]
    fn test_sanitize_go_name_verifier_vars() {
        // Real examples from Jolt verifier to ensure they work
        assert_eq!(
            sanitize_go_name("stage5_sumcheck_r84_1"),
            "Stage5_Sumcheck_R84_1"
        );
        assert_eq!(
            sanitize_go_name("opening_proof_vector_matrix_product[0]"),
            "Opening_Proof_Vector_Matrix_Product_0"
        );
        assert_eq!(
            sanitize_go_name("bytecode_v_init_final"),
            "Bytecode_V_Init_Final"
        );
    }

    // =========================================================================
    // G1 codegen tests
    // =========================================================================

    #[test]
    fn test_g1_var_only_emits_struct_fields_no_method() {
        // When only G1Op::Var entries exist (no arithmetic or constraints),
        // we should get struct fields but no verifyG1Ops method
        let g1_ops = vec![
            G1Op::Var("bf_commit_0".to_string()),
            G1Op::Var("bf_commit_1".to_string()),
        ];
        let g1_constraints = vec![];
        let nodes = vec![];
        let var_names = HashMap::new();

        let result = generate_g1_code(&g1_ops, &g1_constraints, &nodes, &var_names, "TestCircuit");

        assert_eq!(result.struct_fields.len(), 4); // 2 points × 2 coords
        assert!(result.struct_fields.contains(&"Bf_Commit_0_X".to_string()));
        assert!(result.struct_fields.contains(&"Bf_Commit_0_Y".to_string()));
        assert!(result.struct_fields.contains(&"Bf_Commit_1_X".to_string()));
        assert!(result.struct_fields.contains(&"Bf_Commit_1_Y".to_string()));
        assert!(result.method_code.is_empty());
        assert!(!result.needs_sw_grumpkin);
        assert!(!result.needs_emulated);
    }

    #[test]
    fn test_g1_add_emits_curve_add() {
        // G1Op::Add should generate curve.Add call
        let g1_ops = vec![
            G1Op::Var("p0".to_string()),
            G1Op::Var("p1".to_string()),
            G1Op::Add(0, 1),
        ];
        let g1_constraints = vec![];
        let nodes = vec![];
        let var_names = HashMap::new();

        let result = generate_g1_code(&g1_ops, &g1_constraints, &nodes, &var_names, "TestCircuit");

        assert!(result.needs_sw_grumpkin);
        assert!(!result.needs_emulated); // No ScalarMul/MSM
        assert!(result.method_code.contains("curve.Add(g1_0, g1_1)"));
        assert!(result.method_code.contains("sw_grumpkin.G1Affine{X: circuit.P0_X, Y: circuit.P0_Y}"));
    }

    #[test]
    fn test_g1_scalar_mul_emits_bit_decomposition() {
        // G1Op::ScalarMul should generate ToBinary + FromBits + ScalarMul
        let nodes = vec![Node::Atom(Atom::Var(0))];
        let mut var_names = HashMap::new();
        var_names.insert(0, "my_scalar".to_string());

        let g1_ops = vec![
            G1Op::Var("point".to_string()),
            G1Op::ScalarMul(0, 0), // point 0, scalar node 0
        ];
        let g1_constraints = vec![];

        let result = generate_g1_code(&g1_ops, &g1_constraints, &nodes, &var_names, "TestCircuit");

        assert!(result.needs_sw_grumpkin);
        assert!(result.needs_emulated); // ScalarMul needs emulated field
        assert!(result.method_code.contains("api.ToBinary(circuit.My_Scalar, 254)"));
        assert!(result.method_code.contains("scalarField.FromBits(g1_1_bits...)"));
        assert!(result.method_code.contains("curve.ScalarMul(g1_0, g1_1_s)"));
    }

    #[test]
    fn test_g1_constraints_emit_assert_is_equal() {
        let g1_ops = vec![
            G1Op::Var("lhs".to_string()),
            G1Op::Var("rhs".to_string()),
        ];
        let g1_constraints = vec![G1Constraint {
            name: "blindfold_check".to_string(),
            lhs: 0,
            rhs: 1,
        }];
        let nodes = vec![];
        let var_names = HashMap::new();

        let result = generate_g1_code(&g1_ops, &g1_constraints, &nodes, &var_names, "TestCircuit");

        assert!(result.needs_sw_grumpkin);
        assert!(result.method_code.contains("curve.AssertIsEqual(g1_0, g1_1)"));
        assert!(result.method_code.contains("blindfold_check"));
    }

    #[test]
    fn test_g1_sub_emits_neg_then_add() {
        let g1_ops = vec![
            G1Op::Var("a".to_string()),
            G1Op::Var("b".to_string()),
            G1Op::Sub(0, 1),
        ];
        let g1_constraints = vec![];
        let nodes = vec![];
        let var_names = HashMap::new();

        let result = generate_g1_code(&g1_ops, &g1_constraints, &nodes, &var_names, "TestCircuit");

        assert!(result.method_code.contains("curve.Neg(g1_1)"));
        assert!(result.method_code.contains("curve.Add(g1_0, g1_2_neg)"));
    }

    #[test]
    fn test_g1_empty_ops_returns_nothing() {
        let result = generate_g1_code(&[], &[], &[], &HashMap::new(), "TestCircuit");

        assert!(result.struct_fields.is_empty());
        assert!(result.method_code.is_empty());
        assert!(!result.needs_sw_grumpkin);
        assert!(!result.needs_emulated);
    }
}
