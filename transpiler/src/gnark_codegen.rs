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
    expr: Expr,
    /// CSE bindings for this constraint, in declaration order.
    bindings: Vec<(usize, Expr)>,
    /// The assertion type
    assertion: ConstraintAssertion,
    /// Whether the expression is entirely constant
    is_const: bool,
    /// Evaluated constant value (if is_const is true)
    const_val: Option<[u64; 4]>,
    /// Crossval: LHS expression (only for Sub roots in crossval mode)
    crossval_lhs: Option<Expr>,
    /// Crossval: RHS expression (only for Sub roots in crossval mode)
    crossval_rhs: Option<Expr>,
}

/// Assertion type for processed constraints (owned version of Assertion).
#[allow(clippy::enum_variant_names)] // Mirrors zklean_extractor::mle_ast::Assertion naming
enum ConstraintAssertion {
    EqualZero,
    EqualPublicInput { name: String },
    EqualNode { other_expr: Expr },
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
/// let expr = codegen.generate_expr(root_node_id);     // Build structured Expr
/// let bindings = codegen.take_bindings();              // (cse_idx, Expr) pairs
/// ```
///
/// # Per-Constraint Isolation
///
/// Create a fresh `GnarkCodeGen` for each constraint. This gives each sumcheck
/// its own expression tree with isolated CSE variables (`cse_N_*` for constraint N),
/// making debugging easier: when a constraint fails, all `cse_N_*` variables
/// belong to that constraint.
/// Whether codegen is producing global CSE (gcse[i]) or per-constraint CSE (cse_K_i).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CseContext {
    Global,
    Constraint(usize),
}

/// Fragment of a generated Go expression. Keeping CSE/GCSE references
/// structured (instead of baking them into strings) lets the emit loop
/// flip between `cse_K_N` and `cse[N]` at render time without re-parsing
/// the source.
#[derive(Clone, Debug)]
pub(crate) enum ExprFragment {
    Lit(String),
    CseRef(usize),
    GcseRef(usize),
}

pub(crate) type Expr = Vec<ExprFragment>;

/// Conservative size estimate for an [`ExprFragment`]. Used by hoisting to
/// decide when an inline expression would be too big for the Go compiler.
fn fragment_len_estimate(f: &ExprFragment) -> usize {
    match f {
        ExprFragment::Lit(s) => s.len(),
        // `cse[N]` / `gcse[N]` — assume 3 digits, still a coarse bound.
        ExprFragment::CseRef(_) | ExprFragment::GcseRef(_) => 10,
    }
}

/// Render an [`Expr`] to Go source. `constraint_idx` is required whenever a
/// `CseRef` appears and `slice_mode` is false (named-var emission). With
/// `slice_mode = true`, CSE references become `cse[N]` slice indexes and
/// `constraint_idx` is ignored.
fn render_expr(expr: &[ExprFragment], constraint_idx: Option<usize>, slice_mode: bool) -> String {
    let mut out = String::new();
    for frag in expr {
        match frag {
            ExprFragment::Lit(s) => out.push_str(s),
            ExprFragment::CseRef(n) => {
                if slice_mode {
                    out.push_str(&format!("cse[{n}]"));
                } else {
                    let idx = constraint_idx
                        .expect("render_expr: CseRef without constraint_idx (slice_mode=false)");
                    out.push_str(&format!("cse_{idx}_{n}"));
                }
            }
            ExprFragment::GcseRef(n) => out.push_str(&format!("gcse[{n}]")),
        }
    }
    out
}

pub(crate) struct GnarkCodeGen<'a> {
    /// Reference to the node arena (from AstBundle.nodes)
    nodes: &'a [Node],
    /// Reference counts for each NodeId (computed in first pass)
    ref_counts: HashMap<usize, usize>,
    /// Maps NodeId to its resolved expression (inline fragments or a single
    /// CseRef/GcseRef if hoisted).
    pub(crate) generated: HashMap<usize, Expr>,
    /// CSE bindings in declaration order: `(cse_index, rhs_expression)`.
    bindings: Vec<(usize, Expr)>,
    /// Next CSE variable index
    pub(crate) cse_counter: usize,
    /// Maps variable index to input name (e.g., 0 -> "UniSkipCoeff0")
    var_names: &'a HashMap<u16, String>,
    /// CSE context: global (gcse[i]) or per-constraint (cse_K_i)
    cse_context: CseContext,
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
        global_node_map: &HashMap<usize, usize>,
    ) -> Self {
        let mut ref_counts = HashMap::new();

        // Mark ref_counts > 1 for all CSE nodes so they get hoisted.
        // The hoisting order is determined by post-order traversal in generate_expr,
        // which matches the order CSE bindings were computed.
        for &node_id in cse_bindings {
            ref_counts.insert(node_id, 2);
        }

        // Pre-populate `generated` for global CSE nodes so they resolve to gcse[i]
        let mut generated: HashMap<usize, Expr> = HashMap::new();
        for (&node_id, &gcse_idx) in global_node_map {
            generated.insert(node_id, vec![ExprFragment::GcseRef(gcse_idx)]);
        }

        Self {
            nodes,
            ref_counts,
            generated,
            bindings: Vec::new(),
            cse_counter: 0,
            var_names,
            cse_context: CseContext::Constraint(constraint_idx),
            uses_poseidon: false,
        }
    }

    /// Create a GnarkCodeGen for the global CSE block.
    ///
    /// Uses `gcse` naming: hoisted nodes become `gcse[i]`.
    pub(crate) fn new_global(
        nodes: &'a [Node],
        var_names: &'a HashMap<u16, String>,
        global_bindings: &[usize],
    ) -> Self {
        let mut ref_counts = HashMap::new();
        for &node_id in global_bindings {
            ref_counts.insert(node_id, 2);
        }

        Self {
            nodes,
            ref_counts,
            generated: HashMap::new(),
            bindings: Vec::new(),
            cse_counter: 0,
            var_names,
            cse_context: CseContext::Global,
            uses_poseidon: false,
        }
    }

    /// Returns whether poseidon was used in this constraint
    pub(crate) fn uses_poseidon(&self) -> bool {
        self.uses_poseidon
    }

    /// Return all CSE bindings as (index, expression) pairs in declaration order.
    pub(crate) fn take_bindings(&mut self) -> Vec<(usize, Expr)> {
        std::mem::take(&mut self.bindings)
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
    pub(crate) fn generate_expr(&mut self, root_node_id: usize) -> Expr {
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

            // Nodes that already have a cached expression (globally hoisted
            // or resolved earlier in this constraint) short-circuit: their
            // descendants must not be walked, otherwise Phase 2 would emit
            // unreferenced CSE bindings for them.
            if self.generated.contains_key(&node_id) {
                post_order.push(node_id);
                continue;
            }

            // Push this node back with children_processed = true
            stack.push((node_id, true));

            // Push unvisited children (reversed so left-to-right processing due to LIFO)
            for child_id in self.nodes[node_id].child_node_ids().into_iter().rev() {
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
                            let mut expr = Vec::with_capacity(s.len() + r.len() + d.len() + 4);
                            expr.push(ExprFragment::Lit("poseidon.Hash(api, ".to_string()));
                            expr.extend(s);
                            expr.push(ExprFragment::Lit(", ".to_string()));
                            expr.extend(r);
                            expr.push(ExprFragment::Lit(", ".to_string()));
                            expr.extend(d);
                            expr.push(ExprFragment::Lit(")".to_string()));
                            expr
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
                    let mut expr = Vec::with_capacity(a.len() + b_inv.len() + 3);
                    expr.push(ExprFragment::Lit("api.Mul(".to_string()));
                    expr.extend(a);
                    expr.push(ExprFragment::Lit(", api.Inverse(".to_string()));
                    expr.extend(b_inv);
                    expr.push(ExprFragment::Lit("))".to_string()));
                    expr
                }
            };

            // Hoist to CSE variable if referenced more than once OR expression is too large.
            // Large single-use expressions would create massive single-line Go code that
            // overwhelms the Go compiler (e.g., 48MB expression on one line).
            // In global context, only hoist by ref_count — MAX_INLINE_EXPR_LEN could create
            // extra gcse[] entries beyond the pre-allocated slice size.
            const MAX_INLINE_EXPR_LEN: usize = 1000;
            let ref_count = self.ref_counts.get(&node_id).copied().unwrap_or(1);
            let is_global = self.cse_context == CseContext::Global;
            let inline_len = expr.iter().map(fragment_len_estimate).sum::<usize>();
            let should_hoist = if is_global {
                ref_count > 1
            } else {
                ref_count > 1 || inline_len > MAX_INLINE_EXPR_LEN
            };
            if should_hoist {
                let cse_idx = self.cse_counter;
                self.cse_counter += 1;
                let reference = match self.cse_context {
                    CseContext::Global => ExprFragment::GcseRef(cse_idx),
                    CseContext::Constraint(_) => ExprFragment::CseRef(cse_idx),
                };
                self.bindings.push((cse_idx, expr));
                self.generated.insert(node_id, vec![reference]);
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
    fn binary_op(&mut self, op: &str, left: Edge, right: Edge) -> Expr {
        let l = self.edge_to_gnark_iterative(left);
        let r = self.edge_to_gnark_iterative(right);
        let mut expr = Vec::with_capacity(l.len() + r.len() + 3);
        expr.push(ExprFragment::Lit(format!("api.{op}(")));
        expr.extend(l);
        expr.push(ExprFragment::Lit(", ".to_string()));
        expr.extend(r);
        expr.push(ExprFragment::Lit(")".to_string()));
        expr
    }

    /// Generate a unary operation expression (func(api, arg) or func(arg)).
    fn unary_op(&mut self, func: &str, arg: Edge) -> Expr {
        let a = self.edge_to_gnark_iterative(arg);
        // api.Inverse doesn't take api as first arg, poseidon helpers do.
        let prefix = if func.starts_with("api.") {
            format!("{func}(")
        } else {
            format!("{func}(api, ")
        };
        let mut expr = Vec::with_capacity(a.len() + 2);
        expr.push(ExprFragment::Lit(prefix));
        expr.extend(a);
        expr.push(ExprFragment::Lit(")".to_string()));
        expr
    }

    // -------------------------------------------------------------------------
    // Private helper methods
    // -------------------------------------------------------------------------

    /// Generate Gnark expression for an atom
    fn atom_to_gnark(&mut self, atom: Atom) -> Expr {
        match atom {
            Atom::Scalar(value) => vec![ExprFragment::Lit(format_scalar_for_gnark(value))],
            Atom::Var(index) => {
                let name = self
                    .var_names
                    .get(&index)
                    .map(|name| format!("circuit.{}", sanitize_go_name(name)))
                    .unwrap_or_else(|| format!("circuit.X_{index}"));
                vec![ExprFragment::Lit(name)]
            }
            Atom::NamedVar(index) => match self.cse_context {
                CseContext::Global => vec![ExprFragment::GcseRef(index)],
                CseContext::Constraint(_) => vec![ExprFragment::CseRef(index)],
            },
        }
    }

    /// Non-recursive edge_to_gnark that looks up already-generated expressions
    pub(crate) fn edge_to_gnark_iterative(&mut self, edge: Edge) -> Expr {
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

    let (code, stats) = generate_circuit_from_bundle_with_stats(bundle, circuit_name, false);

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

/// Build the Go source for `computeGlobalCse` (plus any split sub-part
/// functions) over the globally-hoisted bindings in `bundle`. Returns
/// `(code, uses_poseidon)`; the boolean feeds the import section.
fn render_global_cse_functions(
    bundle: &zklean_extractor::mle_ast::AstBundle,
    var_names: &HashMap<u16, String>,
    circuit_name: &str,
) -> (String, bool) {
    let global_bindings = &bundle.global_cse.bindings;
    let num_global = global_bindings.len();
    let mut global_codegen = GnarkCodeGen::new_global(&bundle.nodes, var_names, global_bindings);

    // Generate expressions for all global nodes (in topological order)
    for &node_id in global_bindings {
        global_codegen.generate_expr(node_id);
    }

    assert_eq!(
        global_codegen.cse_counter, num_global,
        "global CSE counter ({}) != global bindings count ({}): index mapping would be inconsistent",
        global_codegen.cse_counter, num_global
    );

    let uses_poseidon = global_codegen.uses_poseidon();
    let global_bindings = global_codegen.take_bindings();

    const MAX_GLOBAL_BINDING_LINES: usize = 2000;
    let needs_global_splitting = global_bindings.len() > MAX_GLOBAL_BINDING_LINES;

    let mut output = String::new();

    if needs_global_splitting {
        let num_parts = global_bindings.len().div_ceil(MAX_GLOBAL_BINDING_LINES);
        for part in 0..num_parts {
            let start = part * MAX_GLOBAL_BINDING_LINES;
            let end = std::cmp::min(start + MAX_GLOBAL_BINDING_LINES, global_bindings.len());

            output.push_str(&format!(
                "func (circuit *{circuit_name}) computeGlobalCsePart{part}(api frontend.API, gcse []frontend.Variable) {{\n"
            ));
            for (cse_idx, rhs) in &global_bindings[start..end] {
                let rendered = render_expr(rhs, None, false);
                output.push_str(&format!("\tgcse[{cse_idx}] = {rendered}\n"));
            }
            output.push_str("}\n\n");
        }

        output.push_str(&format!(
            "// computeGlobalCse computes {num_global} nodes shared across multiple constraints.\n"
        ));
        output.push_str(&format!(
            "func (circuit *{circuit_name}) computeGlobalCse(api frontend.API) []frontend.Variable {{\n"
        ));
        output.push_str(&format!(
            "\tgcse := make([]frontend.Variable, {num_global})\n"
        ));
        for part in 0..num_parts {
            output.push_str(&format!(
                "\tcircuit.computeGlobalCsePart{part}(api, gcse)\n"
            ));
        }
        output.push_str("\treturn gcse\n");
        output.push_str("}\n\n");
    } else {
        output.push_str(&format!(
            "// computeGlobalCse computes {num_global} nodes shared across multiple constraints.\n"
        ));
        output.push_str(&format!(
            "func (circuit *{circuit_name}) computeGlobalCse(api frontend.API) []frontend.Variable {{\n"
        ));
        output.push_str(&format!(
            "\tgcse := make([]frontend.Variable, {num_global})\n"
        ));
        for (cse_idx, rhs) in &global_bindings {
            let rendered = render_expr(rhs, None, false);
            output.push_str(&format!("\tgcse[{cse_idx}] = {rendered}\n"));
        }
        output.push_str("\treturn gcse\n");
        output.push_str("}\n\n");
    }

    (output, uses_poseidon)
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
    crossval: bool,
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

    // Build global CSE node map: NodeId → index in gcse slice
    let global_node_map: HashMap<usize, usize> = bundle
        .global_cse
        .bindings
        .iter()
        .enumerate()
        .map(|(idx, &node_id)| (node_id, idx))
        .collect();
    let has_global_cse = !global_node_map.is_empty();
    if bundle
        .global_cse
        .bindings
        .iter()
        .any(|&node_id| node_requires_poseidon_import(&bundle.nodes, node_id))
    {
        stats.uses_poseidon = true;
    }

    for (constraint_idx, c) in bundle.constraints.iter().enumerate() {
        // Use pre-computed CSE bindings from AstBundle
        let cse_bindings = bundle.get_cse_bindings(constraint_idx).unwrap_or(&[]);
        let mut codegen = GnarkCodeGen::new(
            &bundle.nodes,
            &var_names,
            constraint_idx,
            cse_bindings,
            &global_node_map,
        );

        // Generate expression for this constraint.
        // In crossval mode, for Sub roots, generate lhs and rhs separately for api.Println hooks.
        let (expr, crossval_lhs, crossval_rhs): (Expr, Option<Expr>, Option<Expr>) = if crossval {
            if let Node::Sub(lhs_edge, rhs_edge) = bundle.nodes[c.root].clone() {
                // Generate subtrees for both edges first
                if let Edge::NodeRef(id) = lhs_edge {
                    codegen.generate_expr(id);
                }
                if let Edge::NodeRef(id) = rhs_edge {
                    codegen.generate_expr(id);
                }
                // Now resolve edges (subtrees are in codegen.generated)
                let lhs_expr = codegen.edge_to_gnark_iterative(lhs_edge);
                let rhs_expr = codegen.edge_to_gnark_iterative(rhs_edge);
                let mut full_expr: Expr = Vec::with_capacity(lhs_expr.len() + rhs_expr.len() + 3);
                full_expr.push(ExprFragment::Lit("api.Sub(".to_string()));
                full_expr.extend(lhs_expr.clone());
                full_expr.push(ExprFragment::Lit(", ".to_string()));
                full_expr.extend(rhs_expr.clone());
                full_expr.push(ExprFragment::Lit(")".to_string()));
                codegen.generated.insert(c.root, full_expr.clone());
                (full_expr, Some(lhs_expr), Some(rhs_expr))
            } else {
                let expr = codegen.generate_expr(c.root);
                (expr, None, None)
            }
        } else {
            let expr = codegen.generate_expr(c.root);
            (expr, None, None)
        };

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

        let bindings = codegen.take_bindings();

        processed_constraints.push(ProcessedConstraint {
            name: c.name.clone(),
            expr,
            bindings,
            assertion,
            is_const,
            const_val,
            crossval_lhs,
            crossval_rhs,
        });
    }

    stats.total_constraints = processed_constraints.len();

    // Render global CSE first so `uses_poseidon` is known before the imports
    // are written.
    let global_cse_code: String = if has_global_cse {
        let (code, global_uses_poseidon) =
            render_global_cse_functions(bundle, &var_names, &circuit_name);
        if global_uses_poseidon {
            stats.uses_poseidon = true;
        }
        code
    } else {
        String::new()
    };

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

    // Build output
    let mut output = String::new();

    // Package and imports
    if crossval {
        output.push_str("package crossval\n\n");
    } else {
        output.push_str("package jolt_verifier\n\n");
    }
    output.push_str("import (\n");
    output.push_str("\t\"math/big\"\n");
    output.push('\n');
    output.push_str("\t\"github.com/consensys/gnark/frontend\"\n");
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
    //
    // All inputs are marked public. Without PCS verification in the circuit
    // (stage 8 is deferred pending PCS choice), commitments and proof data
    // must be externally verifiable. Once the PCS is integrated, we'll
    // determine which inputs can move to private witness. The exact public
    // surface requires investigation: some inputs may benefit from staying
    // public to avoid in-circuit range checks that the verifier gets for
    // free on public inputs. The WitnessType::PublicStatement / ProofData
    // distinction in AstBundle is already in place for this split.
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

    // Emit global CSE functions (built earlier into `global_cse_code`)
    output.push_str(&global_cse_code);

    // Emit per-constraint helper methods.
    // Each constraint gets its own function to avoid arm64 "branch too far" compiler
    // errors when the entire circuit is in a single Define() method.
    // Large constraints are further split into sub-functions (max ~2000 binding lines each).
    const MAX_BINDING_LINES: usize = 2000;
    let mut constraint_func_names: Vec<String> = Vec::new();

    // Extra parameter for global CSE passthrough
    let gcse_param = if has_global_cse {
        ", gcse []frontend.Variable"
    } else {
        ""
    };

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
                if !crossval {
                    continue;
                }
            } else {
                // Static failure. Skip the body in normal mode (callers check
                // `stats.constant_failed`); keep it under crossval for inspection.
                output.push_str(&format!("// {} STATIC FAILURE: constant != 0\n", pc.name));
                stats.constant_failed += 1;
                stats.failed_names.push(pc.name.clone());
                if !crossval {
                    continue;
                }
            }
        }

        let func_name = format!("verifyConstraint{idx}");
        constraint_func_names.push(func_name.clone());

        let num_bindings = pc.bindings.len();
        let needs_splitting = num_bindings > MAX_BINDING_LINES;
        // In splitting mode, sub-functions share bindings via a `cse` slice,
        // so CSE references render as `cse[N]`. Otherwise they render as
        // `cse_K_N` named vars.
        let slice_mode = needs_splitting;
        let var_name = sanitize_go_name(&pc.name);

        if needs_splitting {
            let num_parts = num_bindings.div_ceil(MAX_BINDING_LINES);

            for part in 0..num_parts {
                let start = part * MAX_BINDING_LINES;
                let end = std::cmp::min(start + MAX_BINDING_LINES, num_bindings);

                output.push_str(&format!(
                    "func (circuit *{circuit_name}) {func_name}Bindings{part}(api frontend.API, cse []frontend.Variable{gcse_param}) {{\n"
                ));
                if part == 0 {
                    output.push_str(&format!("\t// CSE bindings for constraint {idx}\n"));
                }

                for (cse_idx, rhs) in &pc.bindings[start..end] {
                    let rendered = render_expr(rhs, Some(idx), true);
                    output.push_str(&format!("\tcse[{cse_idx}] = {rendered}\n"));
                }

                output.push_str("}\n\n");
            }

            let gcse_arg = if has_global_cse { ", gcse" } else { "" };
            output.push_str(&format!("// {func_name} verifies: {}\n", pc.name));
            output.push_str(&format!(
                "func (circuit *{circuit_name}) {func_name}(api frontend.API{gcse_param}) {{\n"
            ));
            output.push_str(&format!(
                "\tcse := make([]frontend.Variable, {num_bindings})\n"
            ));

            for part in 0..num_parts {
                output.push_str(&format!(
                    "\tcircuit.{func_name}Bindings{part}(api, cse{gcse_arg})\n"
                ));
            }

            let rendered_expr = render_expr(&pc.expr, Some(idx), true);
            output.push_str(&format!("\t{var_name} := {rendered_expr}\n"));
        } else {
            output.push_str(&format!("// {func_name} verifies: {}\n", pc.name));
            output.push_str(&format!(
                "func (circuit *{circuit_name}) {func_name}(api frontend.API{gcse_param}) {{\n"
            ));

            if !pc.bindings.is_empty() {
                output.push_str(&format!("\t// CSE bindings for constraint {idx}\n"));
                for (cse_idx, rhs) in &pc.bindings {
                    let rendered = render_expr(rhs, Some(idx), false);
                    output.push_str(&format!("\tcse_{idx}_{cse_idx} := {rendered}\n"));
                }
            }

            let rendered_expr = render_expr(&pc.expr, Some(idx), false);
            output.push_str(&format!("\t{var_name} := {rendered_expr}\n"));
        }

        // Crossval: emit api.Println hooks for LHS/RHS before the assertion
        if crossval {
            if let (Some(lhs), Some(rhs)) = (&pc.crossval_lhs, &pc.crossval_rhs) {
                let lhs_rendered = render_expr(lhs, Some(idx), slice_mode);
                let rhs_rendered = render_expr(rhs, Some(idx), slice_mode);
                output.push_str(&format!("\tcrossval_lhs_{idx} := {lhs_rendered}\n"));
                output.push_str(&format!("\tcrossval_rhs_{idx} := {rhs_rendered}\n"));
                output.push_str(&format!(
                    "\tapi.Println(\"a{idx}_lhs\", crossval_lhs_{idx})\n"
                ));
                output.push_str(&format!(
                    "\tapi.Println(\"a{idx}_rhs\", crossval_rhs_{idx})\n"
                ));
            } else {
                output.push_str(&format!("\tapi.Println(\"a{idx}_total\", {var_name})\n"));
            }
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
                let rendered = render_expr(other_expr, Some(idx), slice_mode);
                output.push_str(&format!("\tapi.AssertIsEqual({var_name}, {rendered})\n"));
            }
        }

        output.push_str("}\n\n");
    }

    // Define method: calls each per-constraint helper
    output.push_str(&format!(
        "func (circuit *{circuit_name}) Define(api frontend.API) error {{\n"
    ));

    if has_global_cse {
        output.push_str("\tgcse := circuit.computeGlobalCse(api)\n");
        for func_name in &constraint_func_names {
            output.push_str(&format!("\tcircuit.{func_name}(api, gcse)\n"));
        }
    } else {
        for func_name in &constraint_func_names {
            output.push_str(&format!("\tcircuit.{func_name}(api)\n"));
        }
    }

    output.push_str("\treturn nil\n");
    output.push_str("}\n");

    (output, stats)
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

fn node_requires_poseidon_import(nodes: &[Node], root: usize) -> bool {
    let mut stack = vec![root];
    let mut visited = HashSet::new();

    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id) {
            continue;
        }

        match &nodes[node_id] {
            Node::Atom(_) => {}
            Node::TranscriptHash(TranscriptHashData::Poseidon(_), _, _)
            | Node::ByteReverse(_)
            | Node::Truncate128Reverse(_)
            | Node::Truncate128(_)
            | Node::AppendU64Transform(_) => return true,
            node => stack.extend(node_children(node)),
        }
    }

    false
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zklean_extractor::ast_bundle::{Constraint, ConstraintCse, GlobalCse};
    use zklean_extractor::mle_ast::{AstBundle, TargetField, WitnessType};
    use zklean_extractor::Assertion;

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

    #[test]
    fn test_global_poseidon_cse_adds_import() {
        let hash = Node::TranscriptHash(
            TranscriptHashData::Poseidon(Edge::Atom(Atom::Var(2))),
            Edge::Atom(Atom::Var(0)),
            Edge::Atom(Atom::Var(1)),
        );
        let assertion_0 = Node::Sub(Edge::NodeRef(0), Edge::Atom(Atom::Var(3)));
        let assertion_1 = Node::Sub(Edge::NodeRef(0), Edge::Atom(Atom::Var(4)));

        let mut bundle = AstBundle::new();
        bundle.nodes = vec![hash, assertion_0, assertion_1];
        bundle.global_cse = GlobalCse { bindings: vec![0] };
        bundle.constraint_cse = vec![ConstraintCse::default(), ConstraintCse::default()];
        for (idx, name) in ["state", "rounds", "data", "expected_0", "expected_1"]
            .iter()
            .enumerate()
        {
            bundle.add_input(idx as u16, *name, WitnessType::ProofData);
        }
        bundle.constraints = vec![
            Constraint {
                name: "assertion_0".to_string(),
                root: 1,
                assertion: Assertion::EqualZero,
            },
            Constraint {
                name: "assertion_1".to_string(),
                root: 2,
                assertion: Assertion::EqualZero,
            },
        ];

        let (code, stats) = generate_circuit_from_bundle_with_stats(&bundle, "TestCircuit", false);

        assert!(stats.uses_poseidon);
        assert!(code.contains("\"jolt_verifier/poseidon\""));
        assert!(code.contains("poseidon.Hash(api,"));
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

    fn build_bundle_all_poseidon_hoisted() -> AstBundle {
        use zklean_extractor::mle_ast::{Atom, Edge, Node, TranscriptHashData};

        let mut bundle = AstBundle::new();
        bundle.add_input(0, "state", WitnessType::ProofData);
        bundle.add_input(1, "rounds", WitnessType::ProofData);
        bundle.add_input(2, "data", WitnessType::ProofData);

        bundle.nodes.push(Node::TranscriptHash(
            TranscriptHashData::Poseidon(Edge::Atom(Atom::Var(2))),
            Edge::Atom(Atom::Var(0)),
            Edge::Atom(Atom::Var(1)),
        ));

        // Two constraints share the hash node so it gets globally hoisted.
        bundle.add_constraint_eq_zero("a0", 0);
        bundle.add_constraint_eq_zero("a1", 0);

        bundle.run_global_cse();
        bundle.run_cse();
        bundle
    }

    #[test]
    fn test_poseidon_import_emitted_when_all_hoisted() {
        let bundle = build_bundle_all_poseidon_hoisted();
        assert_eq!(bundle.global_cse.bindings.len(), 1);

        let code = generate_circuit_from_bundle(&bundle, "TestCircuit");
        assert!(code.contains("\"jolt_verifier/poseidon\""));
        assert!(code.contains("poseidon.Hash"));
    }

    #[test]
    fn test_global_cse_bindings_deterministic() {
        let reference = build_bundle_all_poseidon_hoisted().global_cse.bindings;
        for _ in 0..30 {
            let run = build_bundle_all_poseidon_hoisted().global_cse.bindings;
            assert_eq!(run, reference);
        }
    }

    #[test]
    fn test_constant_failure_skips_function_emission() {
        use zklean_extractor::mle_ast::{Atom, Node};

        let mut bundle = AstBundle::new();
        // Constant scalar 5 as root: asserts (5 == 0), which is false.
        bundle.nodes.push(Node::Atom(Atom::Scalar([5, 0, 0, 0])));
        bundle.add_constraint_eq_zero("will_fail", 0);

        bundle.run_global_cse();
        bundle.run_cse();

        let (code, stats) = generate_circuit_from_bundle_with_stats(&bundle, "TestCircuit", false);
        assert_eq!(stats.constant_failed, 1);
        assert!(!code.contains("verifyConstraint0"));

        let (crossval_code, _) =
            generate_circuit_from_bundle_with_stats(&bundle, "TestCircuit", true);
        assert!(crossval_code.contains("verifyConstraint0"));
    }

    #[test]
    fn test_render_expr_named_vs_slice() {
        let expr = vec![
            ExprFragment::Lit("api.Mul(".to_string()),
            ExprFragment::CseRef(5),
            ExprFragment::Lit(", ".to_string()),
            ExprFragment::CseRef(12),
            ExprFragment::Lit(")".to_string()),
        ];
        assert_eq!(
            render_expr(&expr, Some(3), false),
            "api.Mul(cse_3_5, cse_3_12)"
        );
        assert_eq!(render_expr(&expr, None, true), "api.Mul(cse[5], cse[12])");
    }

    #[test]
    fn test_render_expr_gcse_ref_is_context_free() {
        let expr = vec![
            ExprFragment::Lit("api.Add(".to_string()),
            ExprFragment::GcseRef(7),
            ExprFragment::Lit(", ".to_string()),
            ExprFragment::CseRef(2),
            ExprFragment::Lit(")".to_string()),
        ];
        assert_eq!(
            render_expr(&expr, Some(0), false),
            "api.Add(gcse[7], cse_0_2)"
        );
        assert_eq!(render_expr(&expr, None, true), "api.Add(gcse[7], cse[2])");
    }

    #[test]
    #[should_panic(expected = "CseRef without constraint_idx")]
    fn test_render_expr_panics_on_cse_ref_without_context() {
        let expr = vec![ExprFragment::CseRef(0)];
        let _ = render_expr(&expr, None, false);
    }
}
