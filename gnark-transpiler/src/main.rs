//! Gnark Transpiler CLI
//!
//! Transpiles Jolt's Stage 1 verifier with Poseidon transcript into Gnark circuits.

use gnark_transpiler::{generate_circuit_from_bundle, PoseidonMleTranscript};
use jolt_core::transcripts::Transcript;
use jolt_core::zkvm::stage1_only_verifier::{
    verify_stage1_with_transcript, Stage1PreambleData, Stage1TranscriptVerificationData,
};
use serde::Deserialize;
use zklean_extractor::mle_ast::{AstBundle, InputKind, MleAst};

/// JSON structure for extracted preamble data
#[derive(Deserialize)]
struct ExtractedPreamble {
    max_input_size: u64,
    max_output_size: u64,
    memory_size: u64,
    inputs: Vec<u8>,
    outputs: Vec<u8>,
    panic: bool,
    ram_k: u64,
    trace_length: u64,
}

/// JSON structure for extracted stage1 data
#[derive(Deserialize)]
struct ExtractedStage1Data {
    preamble: ExtractedPreamble,
    uni_skip_poly_coeffs: Vec<String>,
    sumcheck_round_polys: Vec<Vec<String>>,
    commitments: Vec<Vec<u8>>,
}

/// Number of 32-byte chunks per commitment (384 bytes / 32 = 12)
const CHUNKS_PER_COMMITMENT: usize = 12;

fn main() {
    println!("Gnark Transpiler for Jolt Stage 1 Verifier (with Poseidon Transcript)");
    println!("=====================================================================\n");

    // Load extracted data from JSON
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data_path = format!("{}/data/fib_stage1_data.json", manifest_dir);

    println!("Loading extracted data from: {}", data_path);
    let json_content = std::fs::read_to_string(&data_path).expect("Failed to read data file");
    let extracted: ExtractedStage1Data =
        serde_json::from_str(&json_content).expect("Failed to parse JSON");

    let num_uni_skip_coeffs = extracted.uni_skip_poly_coeffs.len();
    let num_rounds = extracted.sumcheck_round_polys.len();
    let coeffs_per_round = extracted.sumcheck_round_polys[0].len();
    let num_commitments = extracted.commitments.len();

    // Count preamble inputs/outputs chunks
    let preamble_inputs_chunks = (extracted.preamble.inputs.len() + 31) / 32;
    let preamble_outputs_chunks = (extracted.preamble.outputs.len() + 31) / 32;

    println!("\nExtracted data summary:");
    println!("  num_rounds: {}", num_rounds);
    println!("  num_uni_skip_coeffs: {}", num_uni_skip_coeffs);
    println!("  coeffs_per_round: {}", coeffs_per_round);
    println!("  num_commitments: {}", num_commitments);
    println!(
        "  preamble inputs: {} bytes ({} chunks)",
        extracted.preamble.inputs.len(),
        preamble_inputs_chunks
    );
    println!(
        "  preamble outputs: {} bytes ({} chunks)",
        extracted.preamble.outputs.len(),
        preamble_outputs_chunks
    );

    // Track variable indices for input descriptions
    let mut input_descriptions: Vec<(u16, String)> = Vec::new();
    let mut var_idx: u16 = 0;

    // === Create symbolic preamble ===
    // 8 fixed values + inputs chunks + outputs chunks
    println!("\n=== Creating Symbolic Preamble ===");

    let max_input_size = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_max_input_size".to_string()));
    var_idx += 1;

    let max_output_size = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_max_output_size".to_string()));
    var_idx += 1;

    let memory_size = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_memory_size".to_string()));
    var_idx += 1;

    let preamble_inputs: Vec<MleAst> = (0..preamble_inputs_chunks)
        .map(|i| {
            let ast = MleAst::from_var(var_idx);
            input_descriptions.push((var_idx, format!("preamble_input_chunk_{}", i)));
            var_idx += 1;
            ast
        })
        .collect();

    let preamble_outputs: Vec<MleAst> = (0..preamble_outputs_chunks)
        .map(|i| {
            let ast = MleAst::from_var(var_idx);
            input_descriptions.push((var_idx, format!("preamble_output_chunk_{}", i)));
            var_idx += 1;
            ast
        })
        .collect();

    let panic_flag = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_panic".to_string()));
    var_idx += 1;

    let ram_k = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_ram_k".to_string()));
    var_idx += 1;

    let trace_length = MleAst::from_var(var_idx);
    input_descriptions.push((var_idx, "preamble_trace_length".to_string()));
    var_idx += 1;

    let preamble = Stage1PreambleData {
        max_input_size,
        max_output_size,
        memory_size,
        inputs: preamble_inputs,
        outputs: preamble_outputs,
        panic: panic_flag,
        ram_k,
        trace_length,
    };

    println!("  Preamble variables: {} (indices 0..{})", var_idx, var_idx - 1);

    // === Create symbolic commitments ===
    // 41 commitments × 12 chunks each = 492 variables
    println!("\n=== Creating Symbolic Commitments ===");
    let commitments_start_idx = var_idx;

    let commitments: Vec<Vec<MleAst>> = (0..num_commitments)
        .map(|c| {
            (0..CHUNKS_PER_COMMITMENT)
                .map(|chunk| {
                    let ast = MleAst::from_var(var_idx);
                    input_descriptions.push((var_idx, format!("commitment_{}_chunk_{}", c, chunk)));
                    var_idx += 1;
                    ast
                })
                .collect()
        })
        .collect();

    println!(
        "  Commitment variables: {} (indices {}..{})",
        num_commitments * CHUNKS_PER_COMMITMENT,
        commitments_start_idx,
        var_idx - 1
    );

    // === Create symbolic uni-skip coefficients ===
    println!("\n=== Creating Symbolic Uni-Skip Coefficients ===");
    let uni_skip_start_idx = var_idx;

    let uni_skip_poly_coeffs: Vec<MleAst> = (0..num_uni_skip_coeffs)
        .map(|i| {
            let ast = MleAst::from_var(var_idx);
            input_descriptions.push((var_idx, format!("uni_skip_coeff_{}", i)));
            var_idx += 1;
            ast
        })
        .collect();

    println!(
        "  Uni-skip variables: {} (indices {}..{})",
        num_uni_skip_coeffs,
        uni_skip_start_idx,
        var_idx - 1
    );

    // === Create symbolic sumcheck round polynomials ===
    println!("\n=== Creating Symbolic Sumcheck Round Polynomials ===");
    let sumcheck_start_idx = var_idx;

    let sumcheck_round_polys: Vec<Vec<MleAst>> = (0..num_rounds)
        .map(|round| {
            (0..coeffs_per_round)
                .map(|coeff| {
                    let ast = MleAst::from_var(var_idx);
                    input_descriptions.push((var_idx, format!("sumcheck_r{}_c{}", round, coeff)));
                    var_idx += 1;
                    ast
                })
                .collect()
        })
        .collect();

    println!(
        "  Sumcheck variables: {} (indices {}..{})",
        num_rounds * coeffs_per_round,
        sumcheck_start_idx,
        var_idx - 1
    );

    // Build verification data
    let data = Stage1TranscriptVerificationData {
        preamble: Some(preamble),
        commitments,
        uni_skip_poly_coeffs,
        sumcheck_round_polys,
        num_rounds,
    };

    println!("\n=== Total Symbolic Variables: {} ===", var_idx);

    // Create Poseidon transcript for symbolic execution
    let mut transcript: PoseidonMleTranscript = Transcript::new(b"Jolt");

    // Run verification with MleAst and Poseidon transcript
    println!("\nRunning verify_stage1_with_transcript with MleAst + PoseidonMleTranscript...");
    let result = verify_stage1_with_transcript(data, &mut transcript);

    // Build AstBundle from the result
    println!("\n=== Building AstBundle ===");
    let mut bundle = AstBundle::new();

    // Snapshot the arena
    bundle.snapshot_arena();

    // Add input variable descriptions (all are ProofData for Stage 1)
    for (idx, name) in &input_descriptions {
        bundle.add_input(*idx, name.clone(), InputKind::ProofData);
    }

    // Add constraints with their assertion types
    bundle.add_constraint_eq_zero("power_sum_check", result.power_sum_check.root());

    for (i, check) in result.sumcheck_consistency_checks.iter().enumerate() {
        bundle.add_constraint_eq_zero(format!("sumcheck_consistency_{}", i), check.root());
    }

    bundle.add_constraint_eq_public("final_claim", result.final_claim.root(), "expected_final_claim");

    println!("  Nodes in arena: {}", bundle.nodes.len());
    println!("  Constraints: {}", bundle.constraints.len());
    println!("  Input variables: {}", bundle.inputs.len());

    // Generate Gnark circuit from AstBundle
    println!("\n=== Generating Gnark Circuit from AstBundle ===");
    let circuit = generate_circuit_from_bundle(&bundle, "Stage1Circuit");
    println!("Generated circuit: {} bytes", circuit.len());

    // Count Poseidon calls in generated code
    let poseidon_count = circuit.matches("poseidon.Hash").count();
    println!("Poseidon calls in generated code: {}", poseidon_count);

    // Write circuit to file
    let output_dir = format!("{}/go", manifest_dir);
    std::fs::create_dir_all(&output_dir).expect("Failed to create output directory");
    let output_path = format!("{}/stage1_circuit.go", output_dir);
    std::fs::write(&output_path, &circuit).expect("Failed to write circuit file");
    println!("\n✓ Circuit written to: {}", output_path);

    // Also write the AstBundle as JSON for inspection/reuse
    let json_path = format!("{}/stage1_bundle.json", output_dir);
    bundle
        .write_json(std::path::Path::new(&json_path))
        .expect("Failed to write JSON file");
    println!("✓ AstBundle written to: {}", json_path);

    println!("\n✓ SUCCESS: Stage 1 verifier transpiled to Gnark circuit!");
    println!("  - {} symbolic input variables (proof data)", bundle.num_proof_inputs());
    println!("  - {} constraints", bundle.constraints.len());
    println!("  - Challenges derived via Poseidon transcript (in-circuit)");
}
