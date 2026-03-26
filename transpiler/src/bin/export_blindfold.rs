//! Export BlindFold config and witness to JSON for Go gnark circuit testing.
//!
//! Two modes:
//! - `--mode synthetic` (default): Generates random-but-satisfying test data
//! - `--mode real`: Loads a real Jolt ZK proof and extracts BlindFold data
//!
//! Architecture: The BlindFold protocol uses Bn254Curve internally (Fr matches
//! BN254's scalar field, so Pedersen homomorphism holds). For Go export, BN254 G1
//! points are converted to Grumpkin G1 via hash-to-curve (From<Bn254G1>).
//!
//! Usage:
//!   cargo run -p transpiler --bin export_blindfold --features zk
//!   cargo run -p transpiler --bin export_blindfold --features zk -- --mode real

use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalDeserialize;
use ark_std::{UniformRand, Zero};
use clap::{Parser, ValueEnum};
use rand::thread_rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha3::Digest;
use std::path::PathBuf;

use common::jolt_device::JoltDevice;
use jolt_core::curve::{Bn254Curve, Bn254G1, GrumpkinG1, JoltGroupElement};
use jolt_core::field::JoltField;
use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
use jolt_core::poly::commitment::hyrax;
use jolt_core::poly::commitment::pedersen::PedersenGenerators;
use jolt_core::subprotocols::blindfold::*;
use jolt_core::transcripts::Transcript;
use jolt_core::poly::eq_poly::EqPolynomial;
use jolt_core::utils::math::Math;
use jolt_core::zkvm::verifier::JoltVerifierPreprocessing;
use jolt_core::zkvm::RV64IMACProof;
use transpiler::gnark_blindfold_transcript::GnarkBlindFoldTranscript;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ExportMode {
    /// Generate random-but-satisfying test data
    #[default]
    Synthetic,
    /// Load a real Jolt ZK proof and extract BlindFold data
    Real,
}

#[derive(Parser)]
#[command(name = "export_blindfold")]
struct Args {
    /// Export mode: synthetic (random test data) or real (from Jolt ZK proof)
    #[arg(long, default_value = "synthetic", value_enum)]
    mode: ExportMode,

    /// Path to the proof file (only used in real mode)
    #[arg(long, default_value = "/tmp/fib_proof.bin")]
    proof: PathBuf,

    /// Path to the io_device file (only used in real mode)
    #[arg(long, default_value = "/tmp/fib_io_device.bin")]
    io_device: PathBuf,

    /// Path to the preprocessing file (only used in real mode)
    #[arg(long, default_value = "/tmp/jolt_verifier_preprocessing.dat")]
    preprocessing: PathBuf,
}

type F = Fr;
// Use Bn254Curve for the actual protocol (Fr matches BN254 scalar field).
// Grumpkin conversion happens at JSON export time.
type Curve = Bn254Curve;
type G1 = Bn254G1;

// Matches spartan.rs constants (pub(super), not accessible from outside)
const SPARTAN_DEGREE: usize = 3;
const INNER_DEGREE: usize = 2;

/// Create deterministic Pedersen generators for BN254 curve.
/// Mirrors the test-only `PedersenGenerators::<Bn254Curve>::deterministic`.
fn bn254_generators(count: usize) -> PedersenGenerators<Curve> {
    use ark_bn254::G1Projective;

    let hash_to_g1 = |domain: &[u8]| -> Bn254G1 {
        let hash = sha3::Sha3_256::digest(domain);
        let mut rng = ChaCha20Rng::from_seed(hash.into());
        Bn254G1(G1Projective::rand(&mut rng))
    };

    let generators = (0..count)
        .map(|i| {
            let mut domain = b"jolt_pedersen_msg_gen_v1_".to_vec();
            domain.extend_from_slice(&(i as u64).to_le_bytes());
            hash_to_g1(&domain)
        })
        .collect();
    let blinding_generator = hash_to_g1(b"jolt_pedersen_blinding_h2c_v1");
    PedersenGenerators::new(generators, blinding_generator)
}

// ============================================================================
// JSON types matching Go structs in blindfold_config.go
// ============================================================================

#[derive(Serialize)]
struct SparseEntryJSON {
    row: usize,
    col: usize,
    coeff: String,
}

#[derive(Serialize)]
struct G1PointJSON {
    x: String,
    y: String,
    /// BN254 G1 compressed → from_le_bytes_mod_order → hex Fr.
    /// Used by gnark circuit for Poseidon transcript absorption.
    cfr: String,
}

#[derive(Serialize)]
struct BlindFoldConfigJSON {
    num_constraints: usize,
    num_vars: usize,
    inner_num_vars: usize,
    c: usize,
    r_coeff: usize,
    r_prime: usize,
    r_e: usize,
    c_e: usize,
    total_rounds: usize,
    noncoeff_count: usize,
    spartan_degree: usize,
    inner_degree: usize,
    num_round_commitments: usize,
    num_noncoeff_commitments: usize,
    num_e_row_commitments: usize,
    num_eval_commitments: usize,
    num_cross_term_commitments: usize,
    r1cs_a: Vec<SparseEntryJSON>,
    r1cs_b: Vec<SparseEntryJSON>,
    r1cs_c: Vec<SparseEntryJSON>,
}

#[derive(Serialize)]
struct BlindFoldWitnessJSON {
    random_u: String,
    random_round_coms: Vec<G1PointJSON>,
    random_noncoeff: Vec<G1PointJSON>,
    random_e_rows: Vec<G1PointJSON>,
    random_eval_coms: Vec<G1PointJSON>,
    cross_term_coms: Vec<G1PointJSON>,
    real_round_coms: Vec<G1PointJSON>,
    real_eval_coms: Vec<G1PointJSON>,
    real_noncoeff_coms: Vec<G1PointJSON>,
    spartan_coeffs: Vec<Vec<String>>,
    az_r: String,
    bz_r: String,
    cz_r: String,
    inner_coeffs: Vec<Vec<String>>,
    e_r: String,
    w_ry: String,
    folded_u: String,
    pedersen_g: G1PointJSON,
    pedersen_h: G1PointJSON,

    // Baked challenge values (stage 1-7 sumcheck round challenges baked into R1CS)
    // These are the γ values used as evaluation points in R1CS constraints.
    // The combined circuit derives them via ZK Fiat-Shamir and asserts they match.
    baked_challenges: Vec<String>,

    // Debug checkpoints for transcript parity verification
    debug_r_challenge: String,
    debug_tau: Vec<String>,
    debug_rx: Vec<String>,
    debug_ra: String,
    debug_rb: String,
    debug_rc: String,
    debug_pub_az: String,
    debug_pub_bz: String,
    debug_pub_cz: String,
    debug_inner_claim_initial: String,
    debug_ry: Vec<String>,
    debug_lw_at_ry: String,
    debug_inner_claim_final: String,
}

// ZK Fiat-Shamir witness JSON: commitment coordinates + derived challenges
// Used by the combined circuit test (Go side) to verify Poseidon parity.
#[derive(Serialize)]
struct ZKFiatShamirWitnessJSON {
    // Jolt transcript label (hex Fr)
    jolt_label: String,
    // Transcript state right before stages 1-7 (after preamble + commitments).
    // Used to initialize the Go transcript from the correct state.
    // If empty, the Go circuit should start from the jolt_label.
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_n_rounds: Option<u32>,
    // Stage configurations
    stages: Vec<ZKFiatShamirStageJSON>,
    // All derived challenges (flattened across stages), hex Fr
    expected_challenges: Vec<String>,
}

#[derive(Serialize)]
struct ZKFiatShamirStageJSON {
    // Stage label (hex Fr)
    label: String,
    // Number of rounds in this stage
    num_rounds: usize,
    // Commitments per round (currently 1)
    num_commitments_per_round: usize,
    // G1 commitment coordinates for this stage (round_idx * num_coms_per_round)
    commitment_xs: Vec<String>,
    commitment_ys: Vec<String>,
    // BN254 G1 compressed → from_le_bytes_mod_order → hex Fr (for Poseidon transcript)
    commitment_cfrs: Vec<String>,
}

// ============================================================================
// Serialization helpers
// ============================================================================

fn fr_to_hex(f: &F) -> String {
    let bigint = f.into_bigint();
    let bytes = ark_ff::BigInteger::to_bytes_be(&bigint);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a BN254 G1 point to Grumpkin G1 (via hash-to-curve) and serialize.
/// Grumpkin's base field = BN254 Fr, so point coordinates are native in gnark.
/// Also computes `cfr`: the BN254 G1 compressed serialization interpreted as Fr,
/// used for Poseidon transcript absorption in the gnark circuit.
fn bn254_g1_to_grumpkin_json(p: &G1) -> G1PointJSON {
    let grumpkin_point: GrumpkinG1 = GrumpkinG1::from(*p);
    let (x, y) = if grumpkin_point.0.is_zero() {
        ("0".repeat(64), "0".repeat(64))
    } else {
        let affine = grumpkin_point.0.into_affine();
        let x_bytes = ark_ff::BigInteger::to_bytes_be(&affine.x.into_bigint());
        let y_bytes = ark_ff::BigInteger::to_bytes_be(&affine.y.into_bigint());
        (
            x_bytes.iter().map(|b| format!("{:02x}", b)).collect(),
            y_bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        )
    };

    // Compressed Fr from original BN254 G1 point (for transcript absorption).
    let mut buf = vec![];
    ark_serialize::CanonicalSerialize::serialize_compressed(p, &mut buf)
        .expect("BN254 G1 serialization should not fail");
    // Debug: verify compressed size assumption
    static PRINTED_SIZE: std::sync::Once = std::sync::Once::new();
    PRINTED_SIZE.call_once(|| {
        eprintln!("  [DEBUG] BN254 G1 compressed size: {} bytes", buf.len());
    });
    let cfr = Fr::from_le_bytes_mod_order(&buf);

    G1PointJSON {
        x,
        y,
        cfr: fr_to_hex(&cfr),
    }
}

fn sparse_entries_to_json(entries: &[(usize, usize, F)]) -> Vec<SparseEntryJSON> {
    entries
        .iter()
        .map(|(row, col, coeff)| SparseEntryJSON {
            row: *row,
            col: *col,
            coeff: fr_to_hex(coeff),
        })
        .collect()
}

// ============================================================================
// Test scenario construction
// ============================================================================

/// Build BakedPublicInputs from a BlindFoldWitness (replicated from test-only code).
fn build_baked(witness: &BlindFoldWitness<F>, stage_configs: &[StageConfig]) -> BakedPublicInputs<F> {
    let mut challenges = Vec::new();
    for stage in &witness.stages {
        for round in &stage.rounds {
            challenges.push(round.challenge);
        }
    }

    let mut batching_coefficients = Vec::new();
    let initial_claims = witness.initial_claims.clone();

    for (stage_idx, stage) in witness.stages.iter().enumerate() {
        let config = &stage_configs[stage_idx];
        if let Some(ref fout) = config.final_output {
            if fout.constraint.is_none() {
                if let Some(FinalOutputWitness::Linear {
                    batching_coefficients: coeffs,
                    ..
                }) = &stage.final_output
                {
                    batching_coefficients.extend_from_slice(coeffs);
                }
            }
        }
    }

    BakedPublicInputs {
        challenges,
        initial_claims,
        batching_coefficients,
        output_constraint_challenges: Vec::new(),
        input_constraint_challenges: Vec::new(),
        extra_constraint_challenges: Vec::new(),
    }
}

/// Create a test BlindFold instance with BN254 G1 commitments.
fn make_test_instance(
    configs: &[StageConfig],
    blindfold_witness: &BlindFoldWitness<F>,
) -> (
    RelaxedR1CSInstance<F, Curve>,
    RelaxedR1CSWitness<F>,
    VerifierR1CS<F>,
    PedersenGenerators<Curve>,
    Vec<F>,
) {
    let mut rng = thread_rng();

    let baked = build_baked(blindfold_witness, configs);
    let builder = VerifierR1CSBuilder::<F>::new(configs, &baked);
    let r1cs = builder.build();
    let gens = bn254_generators(r1cs.hyrax.C + 1);

    let z = blindfold_witness.assign(&r1cs);
    r1cs.check_satisfaction(&z)
        .expect("R1CS should be satisfied");

    let witness: Vec<F> = z[1..].to_vec();

    let hyrax = &r1cs.hyrax;
    let hyrax_c = hyrax.C;
    let r_coeff = hyrax.R_coeff;
    let r_prime = hyrax.R_prime;

    let mut round_commitments = Vec::new();
    let mut w_row_blindings = vec![F::zero(); r_prime];

    for round_idx in 0..hyrax.total_rounds {
        let row_start = round_idx * hyrax_c;
        let blinding = F::random(&mut rng);
        let commitment = gens.commit(&witness[row_start..row_start + hyrax_c], &blinding);
        w_row_blindings[round_idx] = blinding;
        round_commitments.push(commitment);
    }

    let noncoeff_rows_count = hyrax.noncoeff_rows();
    let mut noncoeff_row_commitments = Vec::new();
    for row in 0..noncoeff_rows_count {
        let start = r_coeff * hyrax_c + row * hyrax_c;
        let end = (start + hyrax_c).min(witness.len());
        let blinding = F::random(&mut rng);
        noncoeff_row_commitments.push(gens.commit(&witness[start..end], &blinding));
        w_row_blindings[r_coeff + row] = blinding;
    }

    let (real_instance, real_witness) = RelaxedR1CSInstance::<F, Curve>::new_non_relaxed(
        &witness,
        r1cs.num_constraints,
        hyrax_c,
        round_commitments,
        noncoeff_row_commitments,
        Vec::new(),
        w_row_blindings,
    );

    (real_instance, real_witness, r1cs, gens, z)
}

/// Simulate ZK Fiat-Shamir: hash random G1 coordinates through Poseidon transcript
/// to derive challenges. This matches Go's `DeriveZKStageChallenges`.
///
/// Each stage gets its own label (matching Jolt's per-stage transcript labels).
///
/// Returns: (challenges, zk_fiat_shamir_data)
fn derive_zk_fiat_shamir_challenges(
    rounds_per_stage: &[usize],
    stage_labels: &[&'static [u8]],
) -> (Vec<F>, ZKFiatShamirWitnessJSON) {
    assert_eq!(rounds_per_stage.len(), stage_labels.len());
    let mut rng = thread_rng();

    // Create a Jolt-style Poseidon transcript
    let mut transcript = GnarkBlindFoldTranscript::new(b"Jolt");
    let jolt_label = Fr::from_le_bytes_mod_order(b"Jolt");

    let mut all_challenges = Vec::new();
    let mut stages_json = Vec::new();

    for stage_idx in 0..rounds_per_stage.len() {
        let num_rounds = rounds_per_stage[stage_idx];
        let label = stage_labels[stage_idx];
        let label_fr = Fr::from_le_bytes_mod_order(label);

        // Append stage label to transcript (matches PoseidonTranscript::raw_append_label)
        transcript.raw_append_label(label);

        let mut commitment_xs = Vec::new();
        let mut commitment_ys = Vec::new();
        let mut commitment_cfrs = Vec::new();

        for _round in 0..num_rounds {
            // Generate random cfr value (simulating compressed BN254 G1 → from_le_bytes_mod_order)
            let cfr = F::rand(&mut rng);
            // Also generate random (x,y) for backwards compatibility
            let x = F::rand(&mut rng);
            let y = F::rand(&mut rng);

            // Absorb into transcript matching PoseidonTranscript::append_commitment:
            // 1. raw_append_label(b"sumcheck_commitment")
            // 2. raw_append_bytes(compressed_32_bytes) = raw_append_scalar(cfr)
            transcript.raw_append_label(b"sumcheck_commitment");
            transcript.raw_append_scalar::<F>(&cfr);

            commitment_xs.push(fr_to_hex(&x));
            commitment_ys.push(fr_to_hex(&y));
            commitment_cfrs.push(fr_to_hex(&cfr));

            // Derive challenge (matches Go's ChallengeScalar())
            let challenge: F = transcript.challenge_scalar_128_bits::<F>();
            all_challenges.push(challenge);
        }

        stages_json.push(ZKFiatShamirStageJSON {
            label: fr_to_hex(&label_fr),
            num_rounds,
            num_commitments_per_round: 1,
            commitment_xs,
            commitment_ys,
            commitment_cfrs,
        });
    }

    let witness_json = ZKFiatShamirWitnessJSON {
        jolt_label: fr_to_hex(&jolt_label),
        transcript_state: None,
        transcript_n_rounds: None,
        stages: stages_json,
        expected_challenges: all_challenges.iter().map(fr_to_hex).collect(),
    };

    (all_challenges, witness_json)
}

/// Build a multi-stage BlindFoldWitness with random-but-satisfying polynomial coefficients.
/// Each stage is an independent chain with its own initial claim.
/// Polynomials satisfy: claim = g(0) + g(1) = 2*c0 + c1 + c2 + ... + cd.
///
/// Returns: (witness, stage_configs)
fn build_multi_stage_witness(
    challenges: &[F],
    rounds_per_stage: &[usize],
    degree: usize,
) -> (BlindFoldWitness<F>, Vec<StageConfig>) {
    let mut rng = thread_rng();
    let mut configs = Vec::new();
    let mut stages = Vec::new();
    let mut initial_claims = Vec::new();
    let mut challenge_offset = 0;

    for (stage_idx, &num_rounds) in rounds_per_stage.iter().enumerate() {
        let mut config = StageConfig::new(num_rounds, degree);
        if stage_idx > 0 {
            config.starts_new_chain = true;
        }
        configs.push(config);

        // Each independent chain gets its own initial claim
        let initial_claim = F::from(55 + stage_idx as u64 * 100);
        initial_claims.push(initial_claim);

        let stage_challenges = &challenges[challenge_offset..challenge_offset + num_rounds];
        challenge_offset += num_rounds;

        let mut rounds = Vec::with_capacity(num_rounds);
        let mut claim = initial_claim;

        for (round_idx, challenge) in stage_challenges.iter().enumerate() {
            let c0: F = if round_idx == 0 { F::from(20u64) } else { F::rand(&mut rng) };
            let mut higher_coeffs: Vec<F> = (2..=degree)
                .map(|_| F::rand(&mut rng))
                .collect();

            let sum_rest: F = F::from(2u64) * c0 + higher_coeffs.iter().copied().sum::<F>();
            let c1 = claim - sum_rest;

            let mut coeffs = vec![c0, c1];
            coeffs.append(&mut higher_coeffs);

            let round = RoundWitness::new(coeffs, *challenge);
            claim = round.evaluate(*challenge);
            rounds.push(round);
        }

        stages.push(StageWitness::new(rounds));
    }

    let witness = BlindFoldWitness::with_multiple_claims(initial_claims, stages);
    (witness, configs)
}

fn main() {
    let args = Args::parse();

    match args.mode {
        ExportMode::Synthetic => synthetic_mode(),
        ExportMode::Real => real_mode(&args),
    }
}

fn synthetic_mode() {
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("go");

    // Production fib(50) stage dimensions: 7 stages, 232 total challenges
    let rounds_per_stage: Vec<usize> = vec![12, 24, 11, 18, 139, 24, 4];
    let stage_labels: Vec<&'static [u8]> = vec![
        b"stage_1", b"stage_2", b"stage_3", b"stage_4",
        b"stage_5", b"stage_6", b"stage_7",
    ];
    let poly_degree = 3; // cubic polynomials (degree 3 = 4 coefficients)
    let total_rounds: usize = rounds_per_stage.iter().sum();

    println!("=== BlindFold Export (Synthetic Mode) ===\n");
    println!("  Stages: {}", rounds_per_stage.len());
    println!("  Rounds per stage: {:?}", rounds_per_stage);
    println!("  Total rounds: {}", total_rounds);
    println!("  Poly degree: {}", poly_degree);

    // =========================================================================
    // Step 1: Derive challenges via Poseidon (simulating ZK Fiat-Shamir)
    // =========================================================================
    println!("\nDeriving challenges via Poseidon transcript...");

    let (challenges, zk_fs_witness) = derive_zk_fiat_shamir_challenges(
        &rounds_per_stage,
        &stage_labels,
    );

    println!("  Challenges derived: {}", challenges.len());
    for (i, c) in challenges.iter().take(5).enumerate() {
        println!("    challenge[{}] = {}", i, fr_to_hex(c));
    }
    if challenges.len() > 5 {
        println!("    ... ({} more)", challenges.len() - 5);
    }

    // =========================================================================
    // Step 1b: Build multi-stage satisfying witness with Poseidon-derived challenges
    // =========================================================================
    println!("\nBuilding multi-stage satisfying witness...");

    let (blindfold_witness, configs) = build_multi_stage_witness(
        &challenges, &rounds_per_stage, poly_degree,
    );

    println!("  Stages: {}", configs.len());
    println!("  Total rounds: {}", total_rounds);
    for (i, config) in configs.iter().enumerate() {
        println!("    Stage {}: {} rounds (chain={})", i+1, config.num_rounds,
            if config.starts_new_chain || i == 0 { "new" } else { "cont" });
    }

    // =========================================================================
    // Step 2: Build R1CS and create instance
    // =========================================================================
    println!("\nBuilding R1CS and instance...");
    let (real_instance, real_witness, r1cs, gens, z) =
        make_test_instance(&configs, &blindfold_witness);

    let hyrax = &r1cs.hyrax;
    let (r_e, c_e) = hyrax.e_grid(r1cs.num_constraints);

    println!("  Constraints: {}", r1cs.num_constraints);
    println!("  Variables: {}", r1cs.num_vars);
    println!(
        "  Hyrax C={}, R_coeff={}, R'={}",
        hyrax.C, hyrax.R_coeff, hyrax.R_prime
    );
    println!("  E grid: R_E={}, C_E={}", r_e, c_e);
    println!("  A entries: {}", r1cs.a.entries.len());
    println!("  B entries: {}", r1cs.b.entries.len());
    println!("  C entries: {}", r1cs.c.entries.len());

    // =========================================================================
    // Step 3: Run BlindFold prover
    // =========================================================================
    println!("\nRunning BlindFold prover...");
    let prover = BlindFoldProver::<F, Curve>::new(&gens, &r1cs, None);
    let mut prover_transcript = GnarkBlindFoldTranscript::new(b"BlindFold");
    let proof = prover.prove(&real_instance, &real_witness, &z, &mut prover_transcript);

    println!("  Spartan rounds: {}", proof.spartan_proof.len());
    println!(
        "  Inner sumcheck rounds: {}",
        proof.inner_sumcheck_proof.len()
    );
    println!(
        "  Random instance round coms: {}",
        proof.random_instance.round_commitments.len()
    );

    // =========================================================================
    // Step 4: Run BlindFold verifier
    // =========================================================================
    println!("\nRunning BlindFold verifier...");
    let verifier = BlindFoldVerifier::<F, Curve>::new(&gens, &r1cs, None);

    let verifier_input = BlindFoldVerifierInput {
        round_commitments: real_instance.round_commitments.clone(),
        eval_commitments: real_instance.eval_commitments.clone(),
    };

    let mut verifier_transcript = GnarkBlindFoldTranscript::new(b"BlindFold");
    match verifier.verify(&proof, &verifier_input, &mut verifier_transcript) {
        Ok(()) => println!("  Verification: PASSED"),
        Err(e) => {
            eprintln!("  Verification FAILED: {e:?}");
            std::process::exit(1);
        }
    }

    // Re-derive e_r and w_ry by replaying the transcript
    let (e_r, w_ry, folded_u, checkpoints) = derive_trusted_values(&proof, &verifier_input, &r1cs);

    println!("  e_r: {}", fr_to_hex(&e_r));
    println!("  w_ry: {}", fr_to_hex(&w_ry));
    println!("  folded_u: {}", fr_to_hex(&folded_u));

    // =========================================================================
    // Step 5: Export config JSON
    // =========================================================================
    println!("\nExporting config...");

    let spartan_num_vars = r1cs.num_constraints.next_power_of_two().log_2();
    let inner_num_vars = (hyrax.R_prime * hyrax.C).log_2();

    let config_json = BlindFoldConfigJSON {
        num_constraints: r1cs.num_constraints,
        num_vars: spartan_num_vars,
        inner_num_vars,
        c: hyrax.C,
        r_coeff: hyrax.R_coeff,
        r_prime: hyrax.R_prime,
        r_e,
        c_e,
        total_rounds: hyrax.total_rounds,
        noncoeff_count: hyrax.noncoeff_count,
        spartan_degree: SPARTAN_DEGREE,
        inner_degree: INNER_DEGREE,
        num_round_commitments: real_instance.round_commitments.len(),
        num_noncoeff_commitments: proof.noncoeff_row_commitments.len(),
        num_e_row_commitments: r_e,
        num_eval_commitments: 0,
        num_cross_term_commitments: proof.cross_term_row_commitments.len(),
        r1cs_a: sparse_entries_to_json(&r1cs.a.entries),
        r1cs_b: sparse_entries_to_json(&r1cs.b.entries),
        r1cs_c: sparse_entries_to_json(&r1cs.c.entries),
    };

    let config_path = output_dir.join("blindfold_config.json");
    let config_str =
        serde_json::to_string_pretty(&config_json).expect("Failed to serialize config");
    std::fs::write(&config_path, &config_str)
        .unwrap_or_else(|e| panic!("Failed to write {config_path:?}: {e}"));
    println!("  Written: {config_path:?} ({} bytes)", config_str.len());

    // =========================================================================
    // Step 6: Export witness JSON
    // =========================================================================
    println!("\nExporting witness...");

    // Convert BN254 G1 commitment points to Grumpkin G1 for Go circuit.
    // PCS checks are deferred in Go, so these are arbitrary valid curve points.
    let witness_json = BlindFoldWitnessJSON {
        random_u: fr_to_hex(&proof.random_instance.u),
        random_round_coms: proof
            .random_instance
            .round_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_noncoeff: proof
            .random_instance
            .noncoeff_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_e_rows: proof
            .random_instance
            .e_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_eval_coms: proof
            .random_instance
            .eval_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        cross_term_coms: proof
            .cross_term_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_round_coms: real_instance
            .round_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_eval_coms: real_instance
            .eval_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_noncoeff_coms: proof
            .noncoeff_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        spartan_coeffs: proof
            .spartan_proof
            .iter()
            .map(|p| {
                p.coeffs_except_linear_term
                    .iter()
                    .map(fr_to_hex)
                    .collect()
            })
            .collect(),
        az_r: fr_to_hex(&proof.az_r),
        bz_r: fr_to_hex(&proof.bz_r),
        cz_r: fr_to_hex(&proof.cz_r),
        inner_coeffs: proof
            .inner_sumcheck_proof
            .iter()
            .map(|p| {
                p.coeffs_except_linear_term
                    .iter()
                    .map(fr_to_hex)
                    .collect()
            })
            .collect(),
        e_r: fr_to_hex(&e_r),
        w_ry: fr_to_hex(&w_ry),
        folded_u: fr_to_hex(&folded_u),
        // Use hash-derived Grumpkin generators for Go circuit
        pedersen_g: bn254_g1_to_grumpkin_json(&gens.message_generators[0]),
        pedersen_h: bn254_g1_to_grumpkin_json(&gens.blinding_generator),

        // Baked challenge values (round challenges baked into R1CS)
        baked_challenges: {
            let baked = build_baked(&blindfold_witness, &configs);
            baked.challenges.iter().map(fr_to_hex).collect()
        },

        // Debug checkpoints
        debug_r_challenge: fr_to_hex(&checkpoints.r_challenge),
        debug_tau: checkpoints.tau.iter().map(fr_to_hex).collect(),
        debug_rx: checkpoints.rx.iter().map(fr_to_hex).collect(),
        debug_ra: fr_to_hex(&checkpoints.ra),
        debug_rb: fr_to_hex(&checkpoints.rb),
        debug_rc: fr_to_hex(&checkpoints.rc),
        debug_pub_az: fr_to_hex(&checkpoints.pub_az),
        debug_pub_bz: fr_to_hex(&checkpoints.pub_bz),
        debug_pub_cz: fr_to_hex(&checkpoints.pub_cz),
        debug_inner_claim_initial: fr_to_hex(&checkpoints.inner_claim_initial),
        debug_ry: checkpoints.ry.iter().map(fr_to_hex).collect(),
        debug_lw_at_ry: fr_to_hex(&checkpoints.lw_at_ry),
        debug_inner_claim_final: fr_to_hex(&checkpoints.inner_claim_final),
    };

    let witness_path = output_dir.join("blindfold_witness.json");
    let witness_str =
        serde_json::to_string_pretty(&witness_json).expect("Failed to serialize witness");
    std::fs::write(&witness_path, &witness_str)
        .unwrap_or_else(|e| panic!("Failed to write {witness_path:?}: {e}"));
    println!("  Written: {witness_path:?} ({} bytes)", witness_str.len());

    // =========================================================================
    // Step 7: Export ZK Fiat-Shamir witness JSON
    // =========================================================================
    println!("\nExporting ZK Fiat-Shamir witness...");

    let fs_witness_path = output_dir.join("zk_fiat_shamir_witness.json");
    let fs_witness_str =
        serde_json::to_string_pretty(&zk_fs_witness).expect("Failed to serialize ZK FS witness");
    std::fs::write(&fs_witness_path, &fs_witness_str)
        .unwrap_or_else(|e| panic!("Failed to write {fs_witness_path:?}: {e}"));
    println!("  Written: {fs_witness_path:?} ({} bytes)", fs_witness_str.len());

    println!("\n=== Export Complete ===");
}

fn real_mode(args: &Args) {
    use jolt_core::transcripts::PoseidonTranscript;
    use jolt_core::zkvm::verifier::BlindFoldExportData;

    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("go");

    println!("=== BlindFold Export (Real Proof Mode) ===\n");

    // =========================================================================
    // Step 1: Load proof, preprocessing, io_device
    // =========================================================================
    println!("Loading proof from: {:?}", args.proof);
    let proof_bytes = std::fs::read(&args.proof)
        .unwrap_or_else(|e| panic!("Failed to read proof file {:?}: {}", args.proof, e));
    let proof: RV64IMACProof = CanonicalDeserialize::deserialize_compressed(&proof_bytes[..])
        .expect("Failed to deserialize proof");
    println!("  trace_length: {}", proof.trace_length);

    println!("Loading io_device from: {:?}", args.io_device);
    let io_bytes = std::fs::read(&args.io_device)
        .unwrap_or_else(|e| panic!("Failed to read io_device file {:?}: {}", args.io_device, e));
    let io_device: JoltDevice = CanonicalDeserialize::deserialize_compressed(&io_bytes[..])
        .expect("Failed to deserialize io_device");
    println!("  inputs: {} bytes", io_device.inputs.len());

    println!("Loading preprocessing from: {:?}", args.preprocessing);
    let preproc_bytes = std::fs::read(&args.preprocessing).unwrap_or_else(|e| {
        panic!("Failed to read preprocessing file {:?}: {}", args.preprocessing, e)
    });
    let preprocessing: JoltVerifierPreprocessing<Fr, DoryCommitmentScheme> =
        CanonicalDeserialize::deserialize_compressed(&preproc_bytes[..])
            .expect("Failed to deserialize preprocessing");
    println!(
        "  zk_generator_g1s: {} points",
        preprocessing.zk_generator_g1s.len()
    );

    // =========================================================================
    // Step 2: Build verifier and extract BlindFold data
    // =========================================================================
    println!("\nRunning Jolt verifier stages 1-8 and extracting BlindFold data...");
    let verifier = jolt_core::zkvm::RV64IMACVerifier::new(
        &preprocessing,
        proof,
        io_device,
        None,
        None,
    )
    .expect("Failed to create verifier");

    let export_data: BlindFoldExportData<Fr, jolt_core::curve::Bn254Curve> = verifier
        .verify_and_export_blindfold_data()
        .expect("BlindFold data extraction failed");

    let r1cs = &export_data.r1cs;
    let hyrax = &r1cs.hyrax;
    let (r_e, c_e) = hyrax.e_grid(r1cs.num_constraints);

    println!("  R1CS constraints: {}", r1cs.num_constraints);
    println!("  R1CS variables: {}", r1cs.num_vars);
    println!("  Stage configs: {}", export_data.stage_configs.len());
    println!("  Round commitments: {}", export_data.round_commitments.len());
    println!(
        "  Hyrax C={}, R_coeff={}, R'={}",
        hyrax.C, hyrax.R_coeff, hyrax.R_prime
    );
    println!("  E grid: R_E={}, C_E={}", r_e, c_e);

    // =========================================================================
    // Step 3: Get Pedersen generators from preprocessing
    // =========================================================================
    let gens_count = pedersen_generator_count_for_r1cs(r1cs);
    println!("\nPedersen generators needed: {} (available: {})",
        gens_count, preprocessing.zk_generator_g1s.len());
    let gens: PedersenGenerators<Curve> = preprocessing.pedersen_generators(gens_count);

    // =========================================================================
    // Step 4: Verify BlindFold proof
    // =========================================================================
    let verifier_input = BlindFoldVerifierInput {
        round_commitments: export_data.round_commitments.clone(),
        eval_commitments: export_data.eval_commitments.clone(),
    };

    println!("\nVerifying BlindFold proof with GnarkBlindFoldTranscript...");
    let bf_verifier = BlindFoldVerifier::<F, Curve>::new(&gens, r1cs, None);
    let mut bf_transcript = GnarkBlindFoldTranscript::new(b"BlindFold");
    match bf_verifier.verify(
        &export_data.blindfold_proof,
        &verifier_input,
        &mut bf_transcript,
    ) {
        Ok(()) => println!("  BlindFold verification: PASSED"),
        Err(e) => {
            eprintln!("  GnarkBlindFoldTranscript verification FAILED: {e:?}");
            eprintln!("  Trying PoseidonTranscript...");
            let bf_verifier2 = BlindFoldVerifier::<F, Curve>::new(&gens, r1cs, None);
            let mut poseidon_transcript = PoseidonTranscript::new(b"BlindFold");
            match bf_verifier2.verify(
                &export_data.blindfold_proof,
                &verifier_input,
                &mut poseidon_transcript,
            ) {
                Ok(()) => {
                    println!("  PoseidonTranscript verification: PASSED");
                    println!("  WARNING: GnarkBlindFoldTranscript differs from PoseidonTranscript!");
                    println!("  The Go circuit's Poseidon must match PoseidonTranscript.");
                }
                Err(e2) => {
                    panic!("BlindFold verification failed with both transcripts: {e2:?}");
                }
            }
        }
    }

    // =========================================================================
    // Step 5: Derive trusted values (replay BlindFold transcript)
    // =========================================================================
    let (e_r, w_ry, folded_u, checkpoints) = derive_trusted_values_with_transcript::<PoseidonTranscript>(
        &export_data.blindfold_proof,
        &verifier_input,
        r1cs,
    );

    println!("\n  e_r: {}", fr_to_hex(&e_r));
    println!("  w_ry: {}", fr_to_hex(&w_ry));
    println!("  folded_u: {}", fr_to_hex(&folded_u));

    // =========================================================================
    // Step 6: Export config JSON
    // =========================================================================
    println!("\nExporting config...");
    let spartan_num_vars = r1cs.num_constraints.next_power_of_two().log_2();
    let inner_num_vars = (hyrax.R_prime * hyrax.C).log_2();

    let config_json = BlindFoldConfigJSON {
        num_constraints: r1cs.num_constraints,
        num_vars: spartan_num_vars,
        inner_num_vars,
        c: hyrax.C,
        r_coeff: hyrax.R_coeff,
        r_prime: hyrax.R_prime,
        r_e,
        c_e,
        total_rounds: hyrax.total_rounds,
        noncoeff_count: hyrax.noncoeff_count,
        spartan_degree: SPARTAN_DEGREE,
        inner_degree: INNER_DEGREE,
        num_round_commitments: export_data.round_commitments.len(),
        num_noncoeff_commitments: export_data.blindfold_proof.noncoeff_row_commitments.len(),
        num_e_row_commitments: r_e,
        num_eval_commitments: export_data.eval_commitments.len(),
        num_cross_term_commitments: export_data.blindfold_proof.cross_term_row_commitments.len(),
        r1cs_a: sparse_entries_to_json(&r1cs.a.entries),
        r1cs_b: sparse_entries_to_json(&r1cs.b.entries),
        r1cs_c: sparse_entries_to_json(&r1cs.c.entries),
    };

    let config_path = output_dir.join("blindfold_config.json");
    let config_str =
        serde_json::to_string_pretty(&config_json).expect("Failed to serialize config");
    std::fs::write(&config_path, &config_str)
        .unwrap_or_else(|e| panic!("Failed to write {config_path:?}: {e}"));
    println!("  Written: {config_path:?} ({} bytes)", config_str.len());

    // =========================================================================
    // Step 7: Export witness JSON
    // =========================================================================
    println!("\nExporting witness...");
    let witness_json = BlindFoldWitnessJSON {
        random_u: fr_to_hex(&export_data.blindfold_proof.random_instance.u),
        random_round_coms: export_data
            .blindfold_proof
            .random_instance
            .round_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_noncoeff: export_data
            .blindfold_proof
            .random_instance
            .noncoeff_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_e_rows: export_data
            .blindfold_proof
            .random_instance
            .e_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        random_eval_coms: export_data
            .blindfold_proof
            .random_instance
            .eval_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        cross_term_coms: export_data
            .blindfold_proof
            .cross_term_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_round_coms: export_data
            .round_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_eval_coms: export_data
            .eval_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        real_noncoeff_coms: export_data
            .blindfold_proof
            .noncoeff_row_commitments
            .iter()
            .map(bn254_g1_to_grumpkin_json)
            .collect(),
        spartan_coeffs: export_data
            .blindfold_proof
            .spartan_proof
            .iter()
            .map(|p| {
                p.coeffs_except_linear_term
                    .iter()
                    .map(fr_to_hex)
                    .collect()
            })
            .collect(),
        az_r: fr_to_hex(&export_data.blindfold_proof.az_r),
        bz_r: fr_to_hex(&export_data.blindfold_proof.bz_r),
        cz_r: fr_to_hex(&export_data.blindfold_proof.cz_r),
        inner_coeffs: export_data
            .blindfold_proof
            .inner_sumcheck_proof
            .iter()
            .map(|p| {
                p.coeffs_except_linear_term
                    .iter()
                    .map(fr_to_hex)
                    .collect()
            })
            .collect(),
        e_r: fr_to_hex(&e_r),
        w_ry: fr_to_hex(&w_ry),
        folded_u: fr_to_hex(&folded_u),
        pedersen_g: bn254_g1_to_grumpkin_json(&gens.message_generators[0]),
        pedersen_h: bn254_g1_to_grumpkin_json(&gens.blinding_generator),
        baked_challenges: export_data.baked.challenges.iter().map(fr_to_hex).collect(),
        debug_r_challenge: fr_to_hex(&checkpoints.r_challenge),
        debug_tau: checkpoints.tau.iter().map(fr_to_hex).collect(),
        debug_rx: checkpoints.rx.iter().map(fr_to_hex).collect(),
        debug_ra: fr_to_hex(&checkpoints.ra),
        debug_rb: fr_to_hex(&checkpoints.rb),
        debug_rc: fr_to_hex(&checkpoints.rc),
        debug_pub_az: fr_to_hex(&checkpoints.pub_az),
        debug_pub_bz: fr_to_hex(&checkpoints.pub_bz),
        debug_pub_cz: fr_to_hex(&checkpoints.pub_cz),
        debug_inner_claim_initial: fr_to_hex(&checkpoints.inner_claim_initial),
        debug_ry: checkpoints.ry.iter().map(fr_to_hex).collect(),
        debug_lw_at_ry: fr_to_hex(&checkpoints.lw_at_ry),
        debug_inner_claim_final: fr_to_hex(&checkpoints.inner_claim_final),
    };

    let witness_path = output_dir.join("blindfold_witness.json");
    let witness_str =
        serde_json::to_string_pretty(&witness_json).expect("Failed to serialize witness");
    std::fs::write(&witness_path, &witness_str)
        .unwrap_or_else(|e| panic!("Failed to write {witness_path:?}: {e}"));
    println!("  Written: {witness_path:?} ({} bytes)", witness_str.len());

    // =========================================================================
    // Step 8: Export ZK Fiat-Shamir witness JSON
    // =========================================================================
    // In real mode, the ZK Fiat-Shamir challenges are derived by the Jolt verifier
    // from real ZK sumcheck round commitments. Export the commitment coordinates
    // so the Go circuit can re-derive them.
    println!("\nExporting ZK Fiat-Shamir witness (real commitments)...");

    let stage_labels: Vec<&'static [u8]> = vec![
        b"stage_1", b"stage_2", b"stage_3", b"stage_4",
        b"stage_5", b"stage_6", b"stage_7",
    ];

    let mut stages_json = Vec::new();
    for (stage_idx, stage_coms) in export_data.stage_round_commitments.iter().enumerate() {
        let label = stage_labels[stage_idx];
        let label_fr = Fr::from_le_bytes_mod_order(label);

        // Convert BN254 G1 points to Grumpkin G1 and extract coordinates + cfr
        let mut commitment_xs = Vec::new();
        let mut commitment_ys = Vec::new();
        let mut commitment_cfrs = Vec::new();
        for com in stage_coms {
            let grumpkin_point: GrumpkinG1 = GrumpkinG1::from(*com);
            let affine = grumpkin_point.0.into_affine();
            let x_bytes = ark_ff::BigInteger::to_bytes_be(&affine.x.into_bigint());
            let y_bytes = ark_ff::BigInteger::to_bytes_be(&affine.y.into_bigint());
            commitment_xs.push(x_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            commitment_ys.push(y_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            // Compute cfr: compressed BN254 G1 → from_le_bytes_mod_order
            let mut buf = vec![];
            ark_serialize::CanonicalSerialize::serialize_compressed(com, &mut buf)
                .expect("BN254 G1 serialization should not fail");
            let cfr = Fr::from_le_bytes_mod_order(&buf);
            commitment_cfrs.push(fr_to_hex(&cfr));
        }

        stages_json.push(ZKFiatShamirStageJSON {
            label: fr_to_hex(&label_fr),
            num_rounds: stage_coms.len(),
            num_commitments_per_round: 1,
            commitment_xs,
            commitment_ys,
            commitment_cfrs,
        });
    }

    // Export transcript state as Fr (LE bytes → from_le_bytes_mod_order)
    let (state_bytes, state_n_rounds) = &export_data.transcript_state_before_stages;
    let state_fr = Fr::from_le_bytes_mod_order(state_bytes);
    println!("  Transcript state before stages: n_rounds={}, state_fr={}", state_n_rounds, fr_to_hex(&state_fr));

    let zk_fs_witness = ZKFiatShamirWitnessJSON {
        jolt_label: fr_to_hex(&Fr::from_le_bytes_mod_order(b"Jolt")),
        transcript_state: Some(fr_to_hex(&state_fr)),
        transcript_n_rounds: Some(*state_n_rounds),
        stages: stages_json,
        expected_challenges: export_data.baked.challenges.iter().map(fr_to_hex).collect(),
    };

    let fs_witness_path = output_dir.join("zk_fiat_shamir_witness.json");
    let fs_witness_str =
        serde_json::to_string_pretty(&zk_fs_witness).expect("Failed to serialize ZK FS witness");
    std::fs::write(&fs_witness_path, &fs_witness_str)
        .unwrap_or_else(|e| panic!("Failed to write {fs_witness_path:?}: {e}"));
    println!("  Written: {fs_witness_path:?} ({} bytes)", fs_witness_str.len());

    println!("\n=== Real Mode Export Complete ===");
    println!("\nNote: The ZK Fiat-Shamir challenges were derived by Jolt's PoseidonTranscript.");
    println!("The Go circuit must use the same Poseidon absorption format to re-derive them.");
}

/// Re-derive e_r, w_ry, and folded_u from the proof by replaying the transcript.
///
/// These values are computed by the verifier during verification.
/// We need them as trusted witness values for the Go circuit (PCS is deferred).
/// Debug checkpoint values for verifying transcript parity with Go.
struct DebugCheckpoints {
    r_challenge: F,
    tau: Vec<F>,
    rx: Vec<F>,
    ra: F,
    rb: F,
    rc: F,
    pub_az: F,
    pub_bz: F,
    pub_cz: F,
    inner_claim_initial: F,
    ry: Vec<F>,
    lw_at_ry: F,
    inner_claim_final: F,
}

fn derive_trusted_values(
    proof: &BlindFoldProof<F, Curve>,
    input: &BlindFoldVerifierInput<Curve>,
    r1cs: &VerifierR1CS<F>,
) -> (F, F, F, DebugCheckpoints) {
    derive_trusted_values_with_transcript::<GnarkBlindFoldTranscript>(proof, input, r1cs)
}

fn derive_trusted_values_with_transcript<T: Transcript>(
    proof: &BlindFoldProof<F, Curve>,
    input: &BlindFoldVerifierInput<Curve>,
    r1cs: &VerifierR1CS<F>,
) -> (F, F, F, DebugCheckpoints) {
    let hyrax = &r1cs.hyrax;
    let (r_e, _c_e) = hyrax.e_grid(r1cs.num_constraints);

    // Reconstruct real instance (same as verifier does)
    let real_instance = RelaxedR1CSInstance::<F, Curve> {
        u: F::ONE,
        round_commitments: input.round_commitments.clone(),
        noncoeff_row_commitments: proof.noncoeff_row_commitments.clone(),
        e_row_commitments: vec![G1::zero(); r_e],
        eval_commitments: input.eval_commitments.clone(),
    };

    // Replay transcript to derive challenges
    let mut transcript = T::new(b"BlindFold");

    transcript.append_label(b"BlindFold_real_instance");
    append_instance_bytes(&real_instance, &mut transcript);

    transcript.append_label(b"BlindFold_random_instance");
    append_instance_bytes(&proof.random_instance, &mut transcript);

    transcript.append_commitments(b"blindfold_cross_term", &proof.cross_term_row_commitments);

    let r: <F as JoltField>::Challenge = transcript.challenge_scalar_optimized::<F>();
    let r_field: F = r.into();

    // Folded u
    let folded_u = F::ONE + r_field * proof.random_instance.u;

    // Spartan transcript
    transcript.append_label(b"BlindFold_spartan");
    let num_vars = r1cs.num_constraints.next_power_of_two().log_2();
    let tau_challenges: Vec<_> = transcript.challenge_vector_optimized::<F>(num_vars);
    let tau_fr: Vec<F> = tau_challenges.iter().map(|c| (*c).into()).collect();

    let mut spartan_challenges = Vec::with_capacity(num_vars);
    let mut claim = F::zero();
    for compressed_poly in &proof.spartan_proof {
        transcript.append_scalars(b"sumcheck_poly", &compressed_poly.coeffs_except_linear_term);
        let r_j: <F as JoltField>::Challenge = transcript.challenge_scalar_optimized::<F>();
        let poly = compressed_poly.decompress(&claim);
        claim = poly.evaluate(&r_j);
        spartan_challenges.push(r_j);
    }

    transcript.append_scalars(b"blindfold_az_bz_cz", &[proof.az_r, proof.bz_r, proof.cz_r]);
    let ra: F = transcript.challenge_scalar_optimized::<F>().into();
    let rb: F = transcript.challenge_scalar_optimized::<F>().into();
    let rc: F = transcript.challenge_scalar_optimized::<F>().into();

    // Compute public contributions (same as verifier)
    let rx: Vec<F> = spartan_challenges.iter().map(|c| (*c).into()).collect();
    let padded = r1cs.num_constraints.next_power_of_two();
    let eq_rx: Vec<F> = EqPolynomial::evals(&rx);

    let a0 = r1cs.a.project_columns(&eq_rx, 0, 1, padded)[0];
    let b0 = r1cs.b.project_columns(&eq_rx, 0, 1, padded)[0];
    let c0 = r1cs.c.project_columns(&eq_rx, 0, 1, padded)[0];
    let pub_az = a0 * folded_u;
    let pub_bz = b0 * folded_u;
    let pub_cz = c0 * folded_u;

    let inner_claim_initial = ra * (proof.az_r - pub_az) + rb * (proof.bz_r - pub_bz) + rc * (proof.cz_r - pub_cz);

    // Inner sumcheck transcript
    let mut inner_challenges = Vec::new();
    let mut inner_claim = inner_claim_initial;

    for compressed_poly in &proof.inner_sumcheck_proof {
        transcript.append_scalars(
            b"inner_sumcheck_poly",
            &compressed_poly.coeffs_except_linear_term,
        );
        let poly = compressed_poly.decompress(&inner_claim);
        let r_j: <F as JoltField>::Challenge = transcript.challenge_scalar_optimized::<F>();
        inner_claim = poly.evaluate(&r_j);
        inner_challenges.push(r_j);
    }

    // Compute e_r from proof opening
    let log_r_e = r_e.log_2();
    let (_rx_row, rx_col) = rx.split_at(log_r_e);
    let e_r = hyrax::evaluate(&proof.e_opening.combined_row, rx_col);

    // Compute w_ry from proof opening
    let log_r_prime = hyrax.log_R_prime();
    let ry_w: Vec<F> = inner_challenges.iter().map(|c| (*c).into()).collect();
    let (_ry_row, ry_col) = ry_w.split_at(log_r_prime);
    let w_ry = hyrax::evaluate(&proof.w_opening.combined_row, ry_col);

    // Compute L_w(ry) for debug verification
    let lw_at_ry = compute_L_w_at_ry(r1cs, &spartan_challenges, &inner_challenges, ra, rb, rc);

    println!("  DEBUG: ra = {}", fr_to_hex(&ra));
    println!("  DEBUG: rb = {}", fr_to_hex(&rb));
    println!("  DEBUG: rc = {}", fr_to_hex(&rc));
    println!("  DEBUG: pub_az = {}", fr_to_hex(&pub_az));
    println!("  DEBUG: pub_bz = {}", fr_to_hex(&pub_bz));
    println!("  DEBUG: pub_cz = {}", fr_to_hex(&pub_cz));
    println!("  DEBUG: inner_claim_initial = {}", fr_to_hex(&inner_claim_initial));
    println!("  DEBUG: inner_claim_final = {}", fr_to_hex(&inner_claim));
    println!("  DEBUG: lw_at_ry = {}", fr_to_hex(&lw_at_ry));
    println!("  DEBUG: w_ry = {}", fr_to_hex(&w_ry));
    println!("  DEBUG: lw_at_ry * w_ry = {}", fr_to_hex(&(lw_at_ry * w_ry)));
    println!("  DEBUG: ry = {:?}", ry_w.iter().map(fr_to_hex).collect::<Vec<_>>());

    let checkpoints = DebugCheckpoints {
        r_challenge: r_field,
        tau: tau_fr,
        rx: rx.clone(),
        ra,
        rb,
        rc,
        pub_az,
        pub_bz,
        pub_cz,
        inner_claim_initial,
        ry: ry_w.clone(),
        lw_at_ry,
        inner_claim_final: inner_claim,
    };

    (e_r, w_ry, folded_u, checkpoints)
}

/// Append instance data to transcript (matching Rust verifier's protocol).
fn append_instance_bytes<T: Transcript>(
    instance: &RelaxedR1CSInstance<F, Curve>,
    transcript: &mut T,
) {
    let mut u_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&instance.u, &mut u_bytes)
        .expect("Serialization should not fail");
    transcript.append_bytes(b"blindfold_u", &u_bytes);
    transcript.append_commitments(b"blindfold_round_coms", &instance.round_commitments);
    transcript.append_commitments(b"blindfold_noncoeff", &instance.noncoeff_row_commitments);
    transcript.append_commitments(b"blindfold_e_rows", &instance.e_row_commitments);
    transcript.append_commitments(b"blindfold_eval_coms", &instance.eval_commitments);
}
