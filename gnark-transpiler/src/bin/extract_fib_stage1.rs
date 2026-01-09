//! Extract Stage 1 inputs from Fibonacci proof
//!
//! This binary runs the Fibonacci prover to generate a real proof,
//! then extracts the Stage 1 verification inputs needed for transpilation.
//! It also computes the expected final_claim by running real verification.

use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;
use common::jolt_device::JoltDevice;
use jolt_core::transcripts::{FrParams, PoseidonTranscript, Transcript};
use jolt_core::zkvm::stage1_only_verifier::{
    verify_stage1_with_transcript, Stage1PreambleData, Stage1TranscriptVerificationData,
};
use jolt_core::zkvm::RV64IMACProof;
use serde::{Deserialize, Serialize};

/// Preamble data (from JoltDevice) for Fiat-Shamir initialization
#[derive(Debug, Serialize, Deserialize)]
pub struct PreambleData {
    pub max_input_size: u64,
    pub max_output_size: u64,
    pub memory_size: u64,
    pub inputs: Vec<u8>,
    pub outputs: Vec<u8>,
    pub panic: bool,
    pub ram_k: usize,
    pub trace_length: usize,
}

/// Extracted Stage 1 data for transpilation
#[derive(Debug, Serialize, Deserialize)]
pub struct Stage1ExtractedData {
    /// Preamble data for Fiat-Shamir initialization
    pub preamble: Option<PreambleData>,
    /// Coefficients of the univariate-skip first round polynomial
    pub uni_skip_poly_coeffs: Vec<String>,
    /// Sumcheck round polynomial coefficients (one vec per round)
    pub sumcheck_round_polys: Vec<Vec<String>>,
    /// Number of rounds
    pub num_rounds: usize,
    /// Trace length
    pub trace_length: usize,
    /// Serialized commitments (for transcript preamble)
    pub commitments: Vec<Vec<u8>>,
    /// Number of commitments
    pub num_commitments: usize,
    /// Expected final claim (computed by running real verifier)
    pub expected_final_claim: String,
}

fn main() {
    println!("=== Extracting Stage 1 Inputs from Fibonacci Proof ===\n");

    let proof_path = "/tmp/fib_proof.bin";
    let io_device_path = "/tmp/fib_io_device.bin";

    if !std::path::Path::new(proof_path).exists() {
        eprintln!("No proof found at {}", proof_path);
        eprintln!("\nTo generate a proof, run the fibonacci example with --save:");
        eprintln!("  cd examples/fibonacci && cargo run --release -- --save");
        return;
    }

    println!("Found existing proof at {}", proof_path);

    // Load proof
    let full_proof = match load_proof_from_file(proof_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load proof: {}", e);
            return;
        }
    };
    println!("Successfully loaded proof!");
    println!("Trace length: {}", full_proof.trace_length);

    // Load io_device (optional - for preamble data)
    let io_device = if std::path::Path::new(io_device_path).exists() {
        match load_io_device_from_file(io_device_path) {
            Ok(device) => {
                println!("Successfully loaded io_device!");
                Some(device)
            }
            Err(e) => {
                eprintln!("Warning: Failed to load io_device: {}", e);
                None
            }
        }
    } else {
        println!("Note: io_device not found at {}, preamble will be empty", io_device_path);
        None
    };

    // Extract Stage 1 data
    let extracted = extract_stage1_data(&full_proof, io_device.as_ref());

    // Print the extracted data
    println!("\n=== Extracted Stage 1 Data ===\n");

    if let Some(preamble) = &extracted.preamble {
        println!("Preamble:");
        println!("  max_input_size: {}", preamble.max_input_size);
        println!("  max_output_size: {}", preamble.max_output_size);
        println!("  memory_size: {}", preamble.memory_size);
        println!("  inputs: {} bytes", preamble.inputs.len());
        println!("  outputs: {} bytes", preamble.outputs.len());
        println!("  panic: {}", preamble.panic);
        println!("  ram_k: {}", preamble.ram_k);
        println!("  trace_length: {}", preamble.trace_length);
    }

    println!("\nTrace length: {}", extracted.trace_length);
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

    println!(
        "\nCommitments ({} total):",
        extracted.num_commitments
    );
    for (i, commitment_bytes) in extracted.commitments.iter().enumerate() {
        println!("  commitment[{}]: {} bytes", i, commitment_bytes.len());
    }

    // Save to JSON
    let json_path = "gnark-transpiler/data/fib_stage1_data.json";
    std::fs::create_dir_all("gnark-transpiler/data")
        .expect("Failed to create data dir");
    let json = serde_json::to_string_pretty(&extracted).expect("Failed to serialize");
    std::fs::write(json_path, &json).expect("Failed to write JSON");
    println!("\n✓ Saved to {}", json_path);
}

fn load_proof_from_file(path: &str) -> Result<RV64IMACProof, Box<dyn std::error::Error>> {
    use ark_serialize::CanonicalDeserialize;

    let bytes = std::fs::read(path)?;
    // Note: serialize_and_print_size uses serialize_compressed
    let full_proof: RV64IMACProof = CanonicalDeserialize::deserialize_compressed(&bytes[..])?;

    Ok(full_proof)
}

fn load_io_device_from_file(path: &str) -> Result<JoltDevice, Box<dyn std::error::Error>> {
    use ark_serialize::CanonicalDeserialize;

    let bytes = std::fs::read(path)?;
    let io_device: JoltDevice = CanonicalDeserialize::deserialize_compressed(&bytes[..])?;

    Ok(io_device)
}

/// Number of 32-byte chunks per commitment (384 bytes / 32 = 12)
const CHUNKS_PER_COMMITMENT: usize = 12;

/// Convert bytes to Fr field element (little-endian)
fn bytes_to_fr(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_le_bytes_mod_order(bytes)
}

fn extract_stage1_data(proof: &RV64IMACProof, io_device: Option<&JoltDevice>) -> Stage1ExtractedData {
    // Extract preamble from io_device if available
    let preamble = io_device.map(|device| PreambleData {
        max_input_size: device.memory_layout.max_input_size,
        max_output_size: device.memory_layout.max_output_size,
        memory_size: device.memory_layout.memory_size,
        inputs: device.inputs.clone(),
        outputs: device.outputs.clone(),
        panic: device.panic,
        ram_k: proof.ram_K,
        trace_length: proof.trace_length,
    });

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

    // Extract serialized commitments
    let commitments: Vec<Vec<u8>> = proof
        .commitments
        .iter()
        .map(|commitment| {
            let mut bytes = Vec::new();
            commitment
                .serialize_compressed(&mut bytes)
                .expect("Failed to serialize commitment");
            bytes
        })
        .collect();

    let num_commitments = commitments.len();

    // =========================================================================
    // Compute expected final_claim by running real Stage 1 verification
    // =========================================================================
    println!("\n=== Computing Expected Final Claim ===");

    // Build verification data with concrete Fr values
    let preamble_fr: Option<Stage1PreambleData<Fr>> = io_device.map(|device| {
        use ark_ff::PrimeField;

        // Convert inputs to Fr chunks (32 bytes each)
        let inputs_chunks: Vec<Fr> = device
            .inputs
            .chunks(32)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                bytes_to_fr(&padded)
            })
            .collect();

        // Convert outputs to Fr chunks
        let outputs_chunks: Vec<Fr> = device
            .outputs
            .chunks(32)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                bytes_to_fr(&padded)
            })
            .collect();

        Stage1PreambleData {
            max_input_size: Fr::from(device.memory_layout.max_input_size),
            max_output_size: Fr::from(device.memory_layout.max_output_size),
            memory_size: Fr::from(device.memory_layout.memory_size),
            inputs: inputs_chunks,
            outputs: outputs_chunks,
            panic: if device.panic { Fr::from(1u64) } else { Fr::from(0u64) },
            ram_k: Fr::from(proof.ram_K as u64),
            trace_length: Fr::from(proof.trace_length as u64),
        }
    });

    // Convert commitments to Fr chunks
    let commitments_fr: Vec<Vec<Fr>> = commitments
        .iter()
        .map(|commitment_bytes| {
            commitment_bytes
                .chunks(32)
                .map(|chunk| {
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    bytes_to_fr(&padded)
                })
                .collect()
        })
        .collect();

    // Extract uni-skip coefficients as Fr
    let uni_skip_coeffs_fr: Vec<Fr> = proof
        .stage1_uni_skip_first_round_proof
        .uni_poly
        .coeffs
        .clone();

    // Extract sumcheck round polys as Fr
    let sumcheck_round_polys_fr: Vec<Vec<Fr>> = proof
        .stage1_sumcheck_proof
        .compressed_polys
        .iter()
        .map(|compressed| compressed.coeffs_except_linear_term.clone())
        .collect();

    // Build verification data
    let verification_data = Stage1TranscriptVerificationData {
        preamble: preamble_fr,
        commitments: commitments_fr,
        uni_skip_poly_coeffs: uni_skip_coeffs_fr,
        sumcheck_round_polys: sumcheck_round_polys_fr,
        num_rounds,
    };

    // Run verification with Poseidon transcript (must match Gnark circuit!)
    let mut transcript: PoseidonTranscript<Fr, FrParams> = Transcript::new(b"Jolt");
    let result = verify_stage1_with_transcript(verification_data, &mut transcript);

    let expected_final_claim = format!("{:?}", result.final_claim);
    println!("  final_claim: {}", expected_final_claim);
    println!("  power_sum_check: {:?}", result.power_sum_check);
    println!(
        "  consistency_checks: {} (all should be 0)",
        result.sumcheck_consistency_checks.len()
    );

    Stage1ExtractedData {
        preamble,
        uni_skip_poly_coeffs: uni_skip_coeffs,
        sumcheck_round_polys,
        num_rounds,
        trace_length: proof.trace_length,
        commitments,
        num_commitments,
        expected_final_claim,
    }
}
