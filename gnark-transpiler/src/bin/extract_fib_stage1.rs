//! Extract Stage 1 inputs from Fibonacci proof
//!
//! This binary runs the Fibonacci prover to generate a real proof,
//! then extracts the Stage 1 verification inputs needed for transpilation.

use jolt_core::zkvm::RV64IMACProof;
use serde::{Deserialize, Serialize};

/// Extracted Stage 1 data for transpilation
#[derive(Debug, Serialize, Deserialize)]
pub struct Stage1ExtractedData {
    /// Coefficients of the univariate-skip first round polynomial
    pub uni_skip_poly_coeffs: Vec<String>,
    /// Sumcheck round polynomial coefficients (one vec per round)
    pub sumcheck_round_polys: Vec<Vec<String>>,
    /// Number of rounds
    pub num_rounds: usize,
    /// Trace length
    pub trace_length: usize,
}

fn main() {
    println!("=== Extracting Stage 1 Inputs from Fibonacci Proof ===\n");

    // We need to build and run the fibonacci prover
    // The fibonacci example uses jolt-sdk macros which generate compile_fib, build_prover_fib, etc.
    // We can't directly call those from here without the guest crate

    // Instead, let's check if there's a serialized proof file we can read
    let proof_path = "/tmp/fib_proof.bin";

    if std::path::Path::new(proof_path).exists() {
        println!("Found existing proof at {}", proof_path);

        // Try to deserialize the proof
        match load_proof_from_file(proof_path) {
            Ok(full_proof) => {
                println!("Successfully loaded proof!");
                println!("Trace length: {}", full_proof.trace_length);

                // Extract Stage 1 data directly from full proof
                let extracted = extract_stage1_data(&full_proof);

                // Print the extracted data
                println!("\n=== Extracted Stage 1 Data ===\n");
                println!("Trace length: {}", extracted.trace_length);
                println!("Num rounds: {}", extracted.num_rounds);
                println!(
                    "\nUni-skip polynomial coefficients ({} total):",
                    extracted.uni_skip_poly_coeffs.len()
                );
                for (i, coeff) in extracted.uni_skip_poly_coeffs.iter().enumerate() {
                    println!("  coeff[{}]: {}", i, coeff);
                }

                println!(
                    "\nSumcheck round polynomials ({} rounds):",
                    extracted.sumcheck_round_polys.len()
                );
                for (round, coeffs) in extracted.sumcheck_round_polys.iter().enumerate() {
                    println!("  Round {} ({} coeffs):", round, coeffs.len());
                    for (i, coeff) in coeffs.iter().enumerate() {
                        println!("    coeff[{}]: {}", i, coeff);
                    }
                }

                // Save to JSON
                let json_path = "gnark-transpiler/data/fib_stage1_data.json";
                std::fs::create_dir_all("gnark-transpiler/data")
                    .expect("Failed to create data dir");
                let json = serde_json::to_string_pretty(&extracted).expect("Failed to serialize");
                std::fs::write(json_path, &json).expect("Failed to write JSON");
                println!("\n✓ Saved to {}", json_path);
            }
            Err(e) => {
                eprintln!("Failed to load proof: {}", e);
                eprintln!("\nTo generate a proof, run the fibonacci example with --save:");
                eprintln!("  cd examples/fibonacci && cargo run --release -- --save");
            }
        }
    } else {
        eprintln!("No proof found at {}", proof_path);
        eprintln!("\nTo generate a proof, run the fibonacci example with --save:");
        eprintln!("  cd examples/fibonacci && cargo run --release -- --save");
    }
}

fn load_proof_from_file(path: &str) -> Result<RV64IMACProof, Box<dyn std::error::Error>> {
    use ark_serialize::CanonicalDeserialize;

    let bytes = std::fs::read(path)?;
    // Note: serialize_and_print_size uses serialize_compressed
    let full_proof: RV64IMACProof = CanonicalDeserialize::deserialize_compressed(&bytes[..])?;

    Ok(full_proof)
}

fn extract_stage1_data(proof: &RV64IMACProof) -> Stage1ExtractedData {
    // Extract uni-skip polynomial coefficients
    let uni_skip_coeffs: Vec<String> = proof
        .stage1_uni_skip_first_round_proof
        .uni_poly
        .coeffs
        .iter()
        .map(|f| format!("{:?}", f))
        .collect();

    // Extract sumcheck round polynomial coefficients
    // Note: These are CompressedUniPoly, so we need to handle the compression
    let sumcheck_round_polys: Vec<Vec<String>> = proof
        .stage1_sumcheck_proof
        .compressed_polys
        .iter()
        .map(|compressed| {
            // For now, just extract the coefficients_except_linear_term
            // The linear term can be derived from hint during verification
            compressed
                .coeffs_except_linear_term
                .iter()
                .map(|f| format!("{:?}", f))
                .collect()
        })
        .collect();

    // Calculate num_rounds from trace length
    let num_rounds = proof.trace_length.trailing_zeros() as usize;

    Stage1ExtractedData {
        uni_skip_poly_coeffs: uni_skip_coeffs,
        sumcheck_round_polys,
        num_rounds,
        trace_length: proof.trace_length,
    }
}
