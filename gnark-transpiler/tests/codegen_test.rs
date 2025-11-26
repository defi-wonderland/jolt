//! Integration tests for gnark-transpiler
//!
//! Tests the full pipeline: Rust → MleAst → Gnark

use ark_bn254::Fr;
use gnark_transpiler::{generate_circuit, generate_gnark_expr, generate_stage1_circuit};
use jolt_core::field::JoltField;
use zklean_extractor::mle_ast::{Atom, MleAst};

// ============================================================================
// Unit tests for atom conversion
// ============================================================================

#[test]
fn test_atom_to_gnark_scalar() {
    let ast = MleAst::from_i128(42);
    let gnark = generate_gnark_expr(ast.root());
    assert_eq!(gnark, "42");
}

// ============================================================================
// Unit tests for simple operations
// ============================================================================

#[test]
fn test_simple_add() {
    let a = MleAst::from_i128(3);
    let b = MleAst::from_i128(5);
    let result = a + b;

    let gnark = generate_gnark_expr(result.root());

    println!("Generated Gnark code: {}", gnark);
    assert!(gnark.contains("api.Add"));
    assert!(gnark.contains("3"));
    assert!(gnark.contains("5"));
}

#[test]
fn test_multiply() {
    let a = MleAst::from_i128(7);
    let b = MleAst::from_i128(11);
    let result = a * b;

    let gnark = generate_gnark_expr(result.root());

    println!("Generated Gnark code: {}", gnark);
    assert!(gnark.contains("api.Mul"));
    assert!(gnark.contains("7"));
    assert!(gnark.contains("11"));
}

#[test]
fn test_complex_expression() {
    // (a + b) * c
    let a = MleAst::from_i128(2);
    let b = MleAst::from_i128(3);
    let c = MleAst::from_i128(4);

    let sum = a + b;
    let result = sum * c;

    let gnark = generate_gnark_expr(result.root());

    println!("Generated Gnark code: {}", gnark);
    assert!(gnark.contains("api.Mul"));
    assert!(gnark.contains("api.Add"));
    assert!(gnark.contains("2"));
    assert!(gnark.contains("3"));
    assert!(gnark.contains("4"));
}

// ============================================================================
// Circuit generation test
// ============================================================================

#[test]
fn test_generate_full_circuit() {
    let a = MleAst::from_i128(10);
    let b = MleAst::from_i128(20);
    let result = a + b;

    let circuit = generate_circuit(result.root(), "TestCircuit");

    println!("Generated circuit:\n{}", circuit);

    assert!(circuit.contains("package jolt_verifier"));
    assert!(circuit.contains("import \"github.com/consensys/gnark/frontend\""));
    assert!(circuit.contains("type TestCircuit struct"));
    assert!(circuit.contains("func (circuit *TestCircuit) Define(api frontend.API) error"));
    assert!(circuit.contains("api.Add"));
    assert!(circuit.contains("api.AssertIsEqual"));
}

// ============================================================================
// KEY TEST: Full pipeline Rust → MleAst → Gnark
// ============================================================================

/// Test the full pipeline: Rust function → MleAst → Gnark
///
/// This is the key test: we take a simple Rust function that uses
/// JoltField operations, run it with MleAst to capture the AST,
/// then transpile to Gnark and verify correctness.
#[test]
fn test_rust_to_ast_to_gnark() {
    // Step 1: Define a simple function using JoltField trait
    fn simple_check<F: JoltField>(a: F, b: F, c: F) -> F {
        (a + b) * c - a
    }

    // Step 2: Run with concrete values to get expected result
    let a_val: i128 = 3;
    let b_val: i128 = 5;
    let c_val: i128 = 7;

    let concrete_result = simple_check(
        Fr::from(a_val as u64),
        Fr::from(b_val as u64),
        Fr::from(c_val as u64),
    );
    // (3 + 5) * 7 - 3 = 8 * 7 - 3 = 56 - 3 = 53
    assert_eq!(concrete_result, Fr::from(53u64));

    // Step 3: Run with MleAst to capture the computation as AST
    let a_ast = MleAst::from_i128(a_val);
    let b_ast = MleAst::from_i128(b_val);
    let c_ast = MleAst::from_i128(c_val);

    let ast_result = simple_check(a_ast, b_ast, c_ast);

    // Step 4: Transpile AST to Gnark code
    let gnark_expr = generate_gnark_expr(ast_result.root());

    println!("Input: (a + b) * c - a where a={}, b={}, c={}", a_val, b_val, c_val);
    println!("Expected result: 53");
    println!("Generated Gnark expression: {}", gnark_expr);

    // Step 5: Verify the generated Gnark code is correct
    // It should be: api.Sub(api.Mul(api.Add(3, 5), 7), 3)
    assert!(gnark_expr.contains("api.Sub"), "Should have Sub for final subtraction");
    assert!(gnark_expr.contains("api.Mul"), "Should have Mul for multiplication");
    assert!(gnark_expr.contains("api.Add"), "Should have Add for addition");
    assert!(gnark_expr.contains("3"), "Should contain constant 3");
    assert!(gnark_expr.contains("5"), "Should contain constant 5");
    assert!(gnark_expr.contains("7"), "Should contain constant 7");
}

// ============================================================================
// Stage 1 Verifier Transpilation Test
// ============================================================================

/// Test transpilation of Stage 1 verification logic.
///
/// This test runs `verify_stage1_for_transpilation` with MleAst inputs
/// to generate an AST that can be transpiled to Gnark.
///
/// Variable layout (indices map to circuit inputs):
/// - tau[0..n]: indices 0..n
/// - r0: index n
/// - sumcheck_challenges[0..m]: indices n+1..n+1+m
/// - uni_skip_poly_coeffs[0..p]: indices n+1+m..n+1+m+p
/// - sumcheck_round_polys flattened: remaining indices
#[test]
fn test_stage1_verifier_transpilation() {
    use jolt_core::zkvm::stage1_only_verifier::{
        Stage1VerificationData, verify_stage1_for_transpilation,
    };

    // Variable index counter
    let mut var_idx: u16 = 0;
    let mut next_var = || {
        let idx = var_idx;
        var_idx += 1;
        MleAst::from_var(idx)
    };

    // Create test data with MleAst VARIABLES (not constants!)
    // This generates circuit inputs like circuit.X_0, circuit.X_1, etc.
    let num_tau = 2;
    let num_sumcheck_challenges = 2;
    let num_uni_skip_coeffs = 3;
    let num_rounds = 2;
    let coeffs_per_round = 2;

    let data = Stage1VerificationData {
        tau: (0..num_tau).map(|_| next_var()).collect(),
        r0: next_var(),
        sumcheck_challenges: (0..num_sumcheck_challenges).map(|_| next_var()).collect(),
        uni_skip_poly_coeffs: (0..num_uni_skip_coeffs).map(|_| next_var()).collect(),
        sumcheck_round_polys: (0..num_rounds)
            .map(|_| (0..coeffs_per_round).map(|_| next_var()).collect())
            .collect(),
        trace_length: 1024,
    };

    println!("Total variables allocated: {}", var_idx);

    // Run verification with MleAst - this builds the AST automatically
    let result = verify_stage1_for_transpilation(data);

    // Transpile each constraint to Gnark
    println!("=== Stage 1 Verifier Transpilation ===");

    let final_claim_expr = generate_gnark_expr(result.final_claim.root());
    println!("Final claim: {}", final_claim_expr);

    let power_sum_expr = generate_gnark_expr(result.power_sum_check.root());
    println!("Power sum check (must == 0): {}", power_sum_expr);

    for (i, check) in result.sumcheck_consistency_checks.iter().enumerate() {
        let check_expr = generate_gnark_expr(check.root());
        println!("Sumcheck round {} consistency (must == 0): {}", i, check_expr);
    }

    // Verify the generated code contains circuit variables
    assert!(final_claim_expr.contains("circuit.X_"), "Should contain circuit variables");
    assert!(power_sum_expr.contains("circuit.X_"), "Power sum should use variables");
}

/// Test full circuit generation with all constraints
#[test]
fn test_generate_stage1_circuit() {
    use jolt_core::zkvm::stage1_only_verifier::{
        Stage1VerificationData, verify_stage1_for_transpilation,
    };

    let mut var_idx: u16 = 0;
    let mut next_var = || {
        let idx = var_idx;
        var_idx += 1;
        MleAst::from_var(idx)
    };

    let data = Stage1VerificationData {
        tau: (0..2).map(|_| next_var()).collect(),
        r0: next_var(),
        sumcheck_challenges: (0..2).map(|_| next_var()).collect(),
        uni_skip_poly_coeffs: (0..3).map(|_| next_var()).collect(),
        sumcheck_round_polys: vec![
            (0..2).map(|_| next_var()).collect(),
            (0..2).map(|_| next_var()).collect(),
        ],
        trace_length: 1024,
    };

    let result = verify_stage1_for_transpilation(data);

    // Generate circuit that enforces all constraints
    let circuit = generate_stage1_circuit(&result, "Stage1Circuit");

    println!("=== Generated Gnark Circuit ===\n{}", circuit);

    assert!(circuit.contains("package jolt_verifier"));
    assert!(circuit.contains("type Stage1Circuit struct"));
    assert!(circuit.contains("func (circuit *Stage1Circuit) Define"));
    assert!(circuit.contains("api.AssertIsEqual"), "Should have constraint assertions");
}
