//! Gnark Transpiler CLI
//!
//! Transpiles Jolt's Stage 1 verifier with Keccak transcript into Gnark circuits.

use gnark_transpiler::KeccakMleTranscript;
use jolt_core::zkvm::stage1_only_verifier::{
    Stage1OnlyPreprocessing, Stage1OnlyProof, Stage1OnlyVerifier,
};
use jolt_core::subprotocols::sumcheck::{SumcheckInstanceProof, UniSkipFirstRoundProof};
use jolt_core::poly::unipoly::UniPoly;
use zklean_extractor::mle_ast::MleAst;

fn main() {
    println!("Gnark Transpiler for Jolt Stage 1 Verifier (Keccak)");
    println!("====================================================\n");

    let trace_length = 8;
    let num_rounds = (trace_length as f64).log2() as usize;

    println!("Creating MleAst proof data...");
    println!("  trace_length: {}", trace_length);
    println!("  num_rounds: {}", num_rounds);

    let mut var_idx = 0u16;

    // Create UniSkipFirstRoundProof with MleAst coefficients
    let uni_skip_coeffs: Vec<MleAst> = (0..=num_rounds)
        .map(|_| {
            let v = MleAst::from_var(var_idx);
            var_idx += 1;
            v
        })
        .collect();

    let uni_skip_poly = UniPoly::from_coeff(uni_skip_coeffs);
    let uni_skip_proof = UniSkipFirstRoundProof::new(uni_skip_poly);

    // Create SumcheckInstanceProof with MleAst round polys
    let round_polys: Vec<UniPoly<MleAst>> = (0..num_rounds)
        .map(|_| {
            let coeffs: Vec<MleAst> = (0..3) // degree 2 polynomial
                .map(|_| {
                    let v = MleAst::from_var(var_idx);
                    var_idx += 1;
                    v
                })
                .collect();
            UniPoly::from_coeff(coeffs)
        })
        .collect();

    let sumcheck_proof = SumcheckInstanceProof::new(round_polys);

    println!("  Total variables used: {}", var_idx);

    // Create proof
    let proof = Stage1OnlyProof::<MleAst, KeccakMleTranscript> {
        uni_skip_first_round_proof: uni_skip_proof,
        sumcheck_proof,
        trace_length,
    };

    // Create preprocessing
    let preprocessing = Stage1OnlyPreprocessing::<MleAst>::new(trace_length);

    // Create dummy program_io
    let program_io = JoltDevice::default();

    // Create dummy commitments
    let commitments: Vec<<DoryCommitmentScheme as jolt_core::poly::commitment::commitment_scheme::CommitmentScheme>::Commitment> = vec![];

    // Create dummy openings
    let openings = Openings::<MleAst>::default();

    println!("\nCreating Stage1OnlyVerifier with KeccakTranscript...");

    // Create the verifier
    match Stage1OnlyVerifier::new::<DoryCommitmentScheme>(
        preprocessing,
        proof,
        openings,
        &program_io,
        &commitments,
        1024, // ram_K
    ) {
        Ok(verifier) => {
            println!("✓ Verifier created");
            println!("\nRunning verify() with MleAst...");

            match verifier.verify() {
                Ok(()) => {
                    println!("✓ Verification completed!");
                    println!("\n✓ SUCCESS: Real verify() works with MleAst + KeccakTranscript!");
                }
                Err(e) => {
                    println!("✗ Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to create verifier: {}", e);
            std::process::exit(1);
        }
    }
}
