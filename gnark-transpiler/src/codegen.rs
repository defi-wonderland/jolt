//! Gnark code generation from zkLean's MLE AST
//!
//! This module traverses zkLean's global NODE_ARENA and generates
//! corresponding Gnark/Go circuit code.

use std::collections::BTreeSet;
use zklean_extractor::mle_ast::{get_node, Atom, Edge, Node};

/// Convert an Edge to Gnark code
fn edge_to_gnark(edge: Edge) -> String {
    match edge {
        Edge::Atom(atom) => atom_to_gnark(atom),
        Edge::NodeRef(node_id) => generate_gnark_expr(node_id),
    }
}

/// Convert an Edge to Gnark code, collecting variable indices
fn edge_to_gnark_with_vars(edge: Edge, vars: &mut BTreeSet<u16>) -> String {
    match edge {
        Edge::Atom(atom) => atom_to_gnark_with_vars(atom, vars),
        Edge::NodeRef(node_id) => generate_gnark_expr_with_vars(node_id, vars),
    }
}

/// Convert an Atom to Gnark code
fn atom_to_gnark(atom: Atom) -> String {
    match atom {
        Atom::Scalar(value) => {
            // Field constant
            format!("{}", value)
        }
        Atom::Var(index) => {
            // Variable reference - maps to circuit input
            format!("circuit.X_{}", index)
        }
        Atom::NamedVar(index) => {
            // Let-bound variable (for CSE)
            format!("temp_{}", index)
        }
    }
}

/// Convert an Atom to Gnark code, collecting variable indices
fn atom_to_gnark_with_vars(atom: Atom, vars: &mut BTreeSet<u16>) -> String {
    match atom {
        Atom::Scalar(value) => format!("{}", value),
        Atom::Var(index) => {
            vars.insert(index);
            format!("circuit.X_{}", index)
        }
        Atom::NamedVar(index) => format!("temp_{}", index),
    }
}

/// Generate Gnark expression from a node in the AST
///
/// Maps AST operations to Gnark API calls:
/// - `Add(a, b)` → `api.Add(a, b)`
/// - `Mul(a, b)` → `api.Mul(a, b)`
/// - etc.
pub fn generate_gnark_expr(node_id: usize) -> String {
    let node = get_node(node_id);

    match node {
        Node::Atom(atom) => atom_to_gnark(atom),

        Node::Add(left, right) => {
            format!(
                "api.Add({}, {})",
                edge_to_gnark(left),
                edge_to_gnark(right)
            )
        }

        Node::Mul(left, right) => {
            format!(
                "api.Mul({}, {})",
                edge_to_gnark(left),
                edge_to_gnark(right)
            )
        }

        Node::Sub(left, right) => {
            format!(
                "api.Sub({}, {})",
                edge_to_gnark(left),
                edge_to_gnark(right)
            )
        }

        Node::Neg(child) => {
            format!("api.Neg({})", edge_to_gnark(child))
        }

        Node::Inv(child) => {
            format!("api.Inverse({})", edge_to_gnark(child))
        }

        Node::Div(left, right) => {
            format!(
                "api.Div({}, {})",
                edge_to_gnark(left),
                edge_to_gnark(right)
            )
        }

        Node::Poseidon2(left, right) => {
            format!(
                "poseidon.Poseidon2(api, {}, {})",
                edge_to_gnark(left),
                edge_to_gnark(right)
            )
        }

        Node::Poseidon4(e1, e2, e3, e4) => {
            format!(
                "poseidon.Poseidon4(api, {}, {}, {}, {})",
                edge_to_gnark(e1),
                edge_to_gnark(e2),
                edge_to_gnark(e3),
                edge_to_gnark(e4)
            )
        }

        Node::Keccak256(input) => {
            format!(
                "keccak.Keccak256(api, {})",
                edge_to_gnark(input)
            )
        }
    }
}

/// Generate Gnark expression while collecting all variable indices used
fn generate_gnark_expr_with_vars(node_id: usize, vars: &mut BTreeSet<u16>) -> String {
    let node = get_node(node_id);

    match node {
        Node::Atom(atom) => atom_to_gnark_with_vars(atom, vars),

        Node::Add(left, right) => {
            format!(
                "api.Add({}, {})",
                edge_to_gnark_with_vars(left, vars),
                edge_to_gnark_with_vars(right, vars)
            )
        }

        Node::Mul(left, right) => {
            format!(
                "api.Mul({}, {})",
                edge_to_gnark_with_vars(left, vars),
                edge_to_gnark_with_vars(right, vars)
            )
        }

        Node::Sub(left, right) => {
            format!(
                "api.Sub({}, {})",
                edge_to_gnark_with_vars(left, vars),
                edge_to_gnark_with_vars(right, vars)
            )
        }

        Node::Neg(child) => {
            format!("api.Neg({})", edge_to_gnark_with_vars(child, vars))
        }

        Node::Inv(child) => {
            format!("api.Inverse({})", edge_to_gnark_with_vars(child, vars))
        }

        Node::Div(left, right) => {
            format!(
                "api.Div({}, {})",
                edge_to_gnark_with_vars(left, vars),
                edge_to_gnark_with_vars(right, vars)
            )
        }

        Node::Poseidon2(left, right) => {
            format!(
                "poseidon.Poseidon2(api, {}, {})",
                edge_to_gnark_with_vars(left, vars),
                edge_to_gnark_with_vars(right, vars)
            )
        }

        Node::Poseidon4(e1, e2, e3, e4) => {
            format!(
                "poseidon.Poseidon4(api, {}, {}, {}, {})",
                edge_to_gnark_with_vars(e1, vars),
                edge_to_gnark_with_vars(e2, vars),
                edge_to_gnark_with_vars(e3, vars),
                edge_to_gnark_with_vars(e4, vars)
            )
        }

        Node::Keccak256(input) => {
            format!(
                "keccak.Keccak256(api, {})",
                edge_to_gnark_with_vars(input, vars)
            )
        }
    }
}

/// Generate a complete Gnark circuit from an AST root
///
/// Creates a Go file with:
/// - Package declaration
/// - Circuit struct with inputs
/// - Define() method with constraints
pub fn generate_circuit(root_node_id: usize, circuit_name: &str) -> String {
    // First pass: collect all variable indices used
    let mut vars = BTreeSet::new();
    let expr = generate_gnark_expr_with_vars(root_node_id, &mut vars);

    let mut output = String::new();

    // Package and imports
    output.push_str("package jolt_verifier\n\n");
    output.push_str("import \"github.com/consensys/gnark/frontend\"\n\n");

    // Circuit struct with all used variables
    output.push_str(&format!("type {} struct {{\n", circuit_name));
    for var_idx in &vars {
        output.push_str(&format!(
            "\tX_{} frontend.Variable `gnark:\",public\"`\n",
            var_idx
        ));
    }
    output.push_str("\tOutput frontend.Variable `gnark:\",public\"`\n");
    output.push_str("}\n\n");

    // Define method
    output.push_str(&format!(
        "func (circuit *{}) Define(api frontend.API) error {{\n",
        circuit_name
    ));
    output.push_str(&format!("\tresult := {}\n", expr));
    output.push_str("\tapi.AssertIsEqual(result, circuit.Output)\n");
    output.push_str("\treturn nil\n");
    output.push_str("}\n");

    output
}

/// Generate a complete Gnark circuit for Stage 1 verification.
///
/// This generates a circuit that:
/// 1. Declares all input variables
/// 2. Enforces power_sum_check == 0
/// 3. Enforces each sumcheck_consistency_check == 0
/// 4. Outputs the final_claim
pub fn generate_stage1_circuit(
    result: &jolt_core::zkvm::stage1_only_verifier::Stage1VerificationResult<zklean_extractor::mle_ast::MleAst>,
    circuit_name: &str,
) -> String {
    // Collect all variables from all constraints
    let mut vars = BTreeSet::new();

    let final_claim_expr = generate_gnark_expr_with_vars(result.final_claim.root(), &mut vars);
    let power_sum_expr = generate_gnark_expr_with_vars(result.power_sum_check.root(), &mut vars);

    let consistency_exprs: Vec<String> = result
        .sumcheck_consistency_checks
        .iter()
        .map(|check| generate_gnark_expr_with_vars(check.root(), &mut vars))
        .collect();

    let mut output = String::new();

    // Package and imports
    output.push_str("package jolt_verifier\n\n");
    output.push_str("import \"github.com/consensys/gnark/frontend\"\n\n");

    // Circuit struct with all used variables
    output.push_str(&format!("type {} struct {{\n", circuit_name));
    for var_idx in &vars {
        output.push_str(&format!(
            "\tX_{} frontend.Variable `gnark:\",public\"`\n",
            var_idx
        ));
    }
    output.push_str("\tExpectedFinalClaim frontend.Variable `gnark:\",public\"`\n");
    output.push_str("}\n\n");

    // Define method
    output.push_str(&format!(
        "func (circuit *{}) Define(api frontend.API) error {{\n",
        circuit_name
    ));

    // Constraint 1: Power sum check == 0
    output.push_str("\t// Power sum check: sum over symmetric domain must equal 0\n");
    output.push_str(&format!("\tpowerSumCheck := {}\n", power_sum_expr));
    output.push_str("\tapi.AssertIsEqual(powerSumCheck, 0)\n\n");

    // Constraint 2: Each sumcheck consistency check == 0
    for (i, expr) in consistency_exprs.iter().enumerate() {
        output.push_str(&format!(
            "\t// Sumcheck round {}: poly(0) + poly(1) - claim == 0\n",
            i
        ));
        output.push_str(&format!("\tconsistencyCheck{} := {}\n", i, expr));
        output.push_str(&format!("\tapi.AssertIsEqual(consistencyCheck{}, 0)\n\n", i));
    }

    // Final claim
    output.push_str("\t// Final claim must match expected\n");
    output.push_str(&format!("\tfinalClaim := {}\n", final_claim_expr));
    output.push_str("\tapi.AssertIsEqual(finalClaim, circuit.ExpectedFinalClaim)\n\n");

    output.push_str("\treturn nil\n");
    output.push_str("}\n");

    output
}

// Tests moved to tests/rust_to_gnark.rs
