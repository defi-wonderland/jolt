//! Run the real Jolt verifier (stages 1-6) with concrete types.
//!
//! With --features debug-expected-output, prints all 15 assertion values
//! and exports them to go/rust_all_assertions.json for comparison with Go circuit.
//!
//! Usage:
//!   cargo run -p gnark-transpiler --bin verify_real --features debug-expected-output

use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
use jolt_core::poly::opening_proof::VerifierOpeningAccumulator;
use jolt_core::transcripts::PoseidonTranscriptFr;
use jolt_core::zkvm::transpilable_verifier::TranspilableVerifier;
use jolt_core::zkvm::verifier::JoltVerifierPreprocessing;
use jolt_core::zkvm::RV64IMACProof;
use common::jolt_device::JoltDevice;

fn main() {
    #[cfg(feature = "debug-expected-output")]
    jolt_core::assertion_debug::reset();

    eprintln!("=== Running Real Jolt Verifier (Stages 1-6) ===\n");

    // Load proof
    let proof_path = "/tmp/fib_proof.bin";
    eprintln!("Loading proof from: {}", proof_path);
    let proof_bytes = std::fs::read(proof_path).expect("Failed to read proof file");
    let proof: RV64IMACProof =
        CanonicalDeserialize::deserialize_compressed(&proof_bytes[..])
            .expect("Failed to deserialize proof");
    eprintln!("  trace_length: {}", proof.trace_length);
    eprintln!("  commitments: {}", proof.commitments.len());

    // Load io_device
    let io_device_path = "/tmp/fib_io_device.bin";
    eprintln!("\nLoading io_device from: {}", io_device_path);
    let io_device_bytes = std::fs::read(io_device_path).expect("Failed to read io_device file");
    let io_device: JoltDevice = CanonicalDeserialize::deserialize_compressed(&io_device_bytes[..])
        .expect("Failed to deserialize io_device");
    eprintln!("  inputs: {} bytes", io_device.inputs.len());
    eprintln!("  outputs: {} bytes", io_device.outputs.len());

    // Load preprocessing
    let preprocessing_path = "/tmp/jolt_verifier_preprocessing.dat";
    eprintln!("\nLoading preprocessing from: {}", preprocessing_path);
    let preprocessing_bytes =
        std::fs::read(preprocessing_path).expect("Failed to read preprocessing file");
    let preprocessing: JoltVerifierPreprocessing<Fr, DoryCommitmentScheme> =
        CanonicalDeserialize::deserialize_compressed(&preprocessing_bytes[..])
            .expect("Failed to deserialize preprocessing");

    // Create real verifier
    eprintln!("\n=== Creating TranspilableVerifier (Real) ===");
    let verifier = TranspilableVerifier::<
        Fr,
        DoryCommitmentScheme,
        PoseidonTranscriptFr,
        VerifierOpeningAccumulator<Fr>,
    >::new(
        &preprocessing,
        proof,
        io_device,
        None, // trusted_advice_commitment
        None, // debug_info
    )
    .expect("Failed to create verifier");

    // Run verification (stages 1-6)
    eprintln!("\n=== Running Real Verification (Stages 1-6) ===");
    eprintln!("=== BEGIN ASSERTION VALUES ===");

    match verifier.verify() {
        Ok(()) => {
            eprintln!("=== END ASSERTION VALUES ===");
            eprintln!("\nVerification completed successfully!");

            #[cfg(feature = "debug-expected-output")]
            {
                let json_path = concat!(env!("CARGO_MANIFEST_DIR"), "/go/rust_all_assertions.json");
                jolt_core::assertion_debug::export_json(json_path);
            }
        }
        Err(e) => {
            eprintln!("=== END ASSERTION VALUES ===");
            eprintln!("\nVerification error: {:?}", e);
            std::process::exit(1);
        }
    }
}
