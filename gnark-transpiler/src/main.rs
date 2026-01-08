//! Gnark Transpiler CLI
//!
//! Transpiles Jolt's Stage 1 verifier with Poseidon transcript into Gnark circuits.

use gnark_transpiler::{generate_circuit_from_bundle, PoseidonMleTranscript};
use jolt_core::transcripts::Transcript;
use jolt_core::zkvm::stage1_only_verifier::{
    verify_stage1_with_transcript, Stage1TranscriptVerificationData,
};
use zklean_extractor::mle_ast::{AstBundle, InputKind, MleAst};

fn main() {
    println!("Gnark Transpiler for Jolt Stage 1 Verifier (with Poseidon Transcript)");
    println!("=====================================================================\n");

    // Parameters from real Fibonacci proof (trace_length=2048)
    let num_rounds: usize = 12;
    let num_uni_skip_coeffs: usize = 28;
    let coeffs_per_round: usize = 3;

    println!("Creating symbolic verification data (from Fibonacci proof):");
    println!("  num_rounds: {}", num_rounds);
    println!("  num_uni_skip_coeffs: {}", num_uni_skip_coeffs);
    println!("  coeffs_per_round: {}", coeffs_per_round);

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

    let var_idx = num_uni_skip_coeffs + num_rounds * coeffs_per_round;

    let data = Stage1TranscriptVerificationData {
        uni_skip_poly_coeffs,
        sumcheck_round_polys,
        num_rounds,
    };

    println!("\nTotal symbolic variables allocated: {}", var_idx);

    // Create Poseidon transcript for symbolic execution
    let mut transcript: PoseidonMleTranscript = Transcript::new(b"jolt");

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
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
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
