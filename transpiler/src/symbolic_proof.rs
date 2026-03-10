//! Convert a real JoltProof to a symbolic JoltProof for transpilation.
//!
//! # Overview
//!
//! This module creates symbolic versions of proof data structures. During symbolic
//! execution, we need a `JoltProof<MleAst>` where each field element is replaced
//! with an `MleAst::Var(index)`, a unique symbolic variable.
//!
//! # Key Function
//!
//! - [`symbolize_proof`]: Convert a concrete `RV64IMACProof` to symbolic form
//!
//! # How It Works
//!
//! The `VarAllocator` simultaneously:
//! 1. Allocates fresh symbolic variables (`MleAst::Var(index)`)
//! 2. Records the corresponding concrete witness values
//!
//! This single-pass approach makes witness/symbolization mismatches structurally
//! impossible - both are recorded in the same function call.
//!
//! # Commitment Serialization
//!
//! Dory commitments are 384-byte elliptic curve points. They're split into 12 chunks
//! of 32 bytes each (to fit in BN254 field elements). The serialization uses:
//!
//! - `serialize_uncompressed` (not compressed)
//! - LE byte order (no reversal needed for circuit)
//!
//! Dory will probably be replaced in future iterations,
//! the transpilation code will need to be updated in that case.
//!
//! This must match exactly how the Poseidon transcript hashes commitments.

use crate::symbolic_traits::ast_commitment_scheme::{AstCommitmentScheme, AstProof};
use crate::symbolic_traits::ast_curve::{AstCurve, AstGroupElement};
use crate::symbolic_traits::opening_accumulator::AstOpeningAccumulator;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use jolt_core::curve::JoltCurve;
use jolt_core::zkvm::PedersenCurve;
#[cfg(not(feature = "zk"))]
use jolt_core::poly::opening_proof::OpeningPoint;
use jolt_core::poly::unipoly::CompressedUniPoly;
#[cfg(feature = "zk")]
use jolt_core::subprotocols::blindfold::{BlindFoldProof, RelaxedR1CSInstance};
use jolt_core::subprotocols::sumcheck::{SumcheckInstanceProof, ZkSumcheckProof};
use jolt_core::subprotocols::univariate_skip::{
    UniSkipFirstRoundProof, UniSkipFirstRoundProofVariant, ZkUniSkipFirstRoundProof,
};
use jolt_core::transcripts::Transcript;
#[cfg(not(feature = "zk"))]
use jolt_core::zkvm::proof_serialization::Claims;
use jolt_core::zkvm::proof_serialization::JoltProof;
use jolt_core::zkvm::RV64IMACProof;
#[cfg(not(feature = "zk"))]
use std::collections::BTreeMap;
use zklean_extractor::mle_ast::{MleAst, TargetField};
use zklean_extractor::{store_g1_chunks, AstCommitment};

/// Tracks variable index allocation and witness values during symbolization.
///
/// Each call to `alloc_with_value()` returns a fresh `MleAst::Var(index)` with a unique index,
/// while simultaneously recording the concrete witness value. This ensures witness values
/// are always in sync with symbolic variable allocation, making mismatch bugs structurally
/// impossible.
///
/// # Field Kind Tracking
///
/// Variables can be allocated for different target fields (Fr or Fq). The allocator
/// tracks field kind per variable to enable correct codegen. Currently only Fr is
/// supported at codegen time; Fq variables will panic with a clear error.
///
/// The allocator records:
/// - Human-readable descriptions for Go struct field names (e.g., `Stage1_Sumcheck_R0_0`)
/// - Concrete witness values as decimal strings (for JSON serialization to Go)
/// - Field kind per variable (Fr for native, Fq for emulated arithmetic)
pub struct VarAllocator {
    next_idx: u16,
    /// (index, name, target_field) tuples for each allocated variable.
    descriptions: Vec<(u16, String, TargetField)>,
    /// Witness values indexed by variable index, stored as decimal strings.
    witness_values: Vec<String>,
    /// G1 affine coordinate witness values: (go_name, x_decimal, y_decimal).
    /// For Grumpkin points, X and Y are BN254 Fr elements (native in the circuit).
    g1_witness_coords: Vec<(String, String, String)>,
}

impl VarAllocator {
    pub fn new() -> Self {
        Self {
            next_idx: 0,
            descriptions: Vec::new(),
            witness_values: Vec::new(),
            g1_witness_coords: Vec::new(),
        }
    }

    /// Allocate a single variable with its concrete value (Fr field, default).
    ///
    /// This is the primary allocation method for stages 1-7.
    pub fn alloc_with_value(&mut self, description: &str, value: &ark_bn254::Fr) -> MleAst {
        self.alloc_with_value_and_field(description, value, TargetField::Fr)
    }

    /// Allocate a single variable with explicit target field.
    ///
    /// # Arguments
    /// * `description`: Human-readable name for codegen
    /// * `value`: Concrete witness value (as Fr, converted to decimal string)
    /// * `target_field`: Target field (Fr for native, Fq for emulated)
    ///
    /// # Note
    /// The value is stored as a decimal string regardless of field.
    /// For Fq values, ensure the value fits in the Fq modulus.
    pub fn alloc_with_value_and_field(
        &mut self,
        description: &str,
        value: &ark_bn254::Fr,
        target_field: TargetField,
    ) -> MleAst {
        use ark_ff::PrimeField;
        let idx = self.next_idx;
        self.descriptions
            .push((idx, description.to_string(), target_field));
        self.witness_values.push(format!("{}", value.into_bigint()));
        self.next_idx += 1;
        MleAst::from_var(idx)
    }

    /// Allocate N variables with their concrete values (Fr field, default).
    ///
    /// Both symbolic variables and witness values are recorded in the same call,
    /// guaranteeing they stay in sync.
    pub fn alloc_n_with_values(&mut self, values: &[ark_bn254::Fr], prefix: &str) -> Vec<MleAst> {
        self.alloc_n_with_values_and_field(values, prefix, TargetField::Fr)
    }

    /// Allocate N variables with explicit field kind.
    pub fn alloc_n_with_values_and_field(
        &mut self,
        values: &[ark_bn254::Fr],
        prefix: &str,
        target_field: TargetField,
    ) -> Vec<MleAst> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                self.alloc_with_value_and_field(&format!("{prefix}_{i}"), v, target_field)
            })
            .collect()
    }

    pub fn next_idx(&self) -> u16 {
        self.next_idx
    }

    /// Get descriptions with target fields for AstBundle population.
    pub fn descriptions_with_fields(&self) -> &[(u16, String, TargetField)] {
        &self.descriptions
    }

    /// Get descriptions without field kinds (backward compatible iterator).
    pub fn descriptions(&self) -> impl Iterator<Item = (u16, &str)> + '_ {
        self.descriptions
            .iter()
            .map(|(idx, name, _)| (*idx, name.as_str()))
    }

    /// Get witness values as a HashMap for JSON serialization.
    pub fn witness_values(&self) -> std::collections::HashMap<usize, String> {
        self.witness_values
            .iter()
            .enumerate()
            .map(|(i, v)| (i, v.clone()))
            .collect()
    }

    /// Check if any variables with the specified field kind were allocated.
    pub fn has_variables_for_field(&self, field: TargetField) -> bool {
        self.descriptions.iter().any(|(_, _, tf)| *tf == field)
    }

    /// Get G1 affine coordinate witness values for the witness JSON.
    ///
    /// Returns (go_name, x_decimal, y_decimal) for each G1 variable.
    /// These correspond to `{Name}_X` and `{Name}_Y` struct fields in the gnark circuit.
    pub fn g1_witness_coords(&self) -> &[(String, String, String)] {
        &self.g1_witness_coords
    }

    /// Allocate variables for a commitment's 12 chunks and record witness values (Fr field).
    ///
    /// Commitments are serialized as uncompressed LE bytes,
    /// then split into 12 × 32-byte chunks (each fits in a BN254 field element).
    pub fn alloc_commitment<T: CanonicalSerialize>(
        &mut self,
        commitment: &T,
        prefix: &str,
    ) -> Vec<MleAst> {
        let chunks = commitment_to_field_chunks(commitment);
        self.alloc_n_with_values(&chunks, prefix)
    }

    /// Allocate variables for a compressed G1 point and return an AstGroupElement.
    ///
    /// The point is serialized compressed (33 bytes for BN254 G1), split into
    /// 32-byte chunks, converted to field elements, and stored in G1_CHUNK_STORE.
    /// The returned AstGroupElement carries the store index so that
    /// `serialize_compressed` → `set_pending_g1_chunks` tunnels the symbolic
    /// chunks to `PoseidonAstTranscript::append_commitment`.
    pub fn alloc_g1_compressed(
        &mut self,
        point: &impl CanonicalSerialize,
        prefix: &str,
    ) -> AstGroupElement {
        let chunks = g1_compressed_to_field_chunks(point);
        let symbolic_chunks = self.alloc_n_with_values(&chunks, prefix);
        let idx = store_g1_chunks(symbolic_chunks);
        AstGroupElement::new(idx)
    }

    /// Allocate a G1 point variable with both Fiat-Shamir chunks and G1 operation recording.
    ///
    /// This is the Phase 3 variant of `alloc_g1_compressed`. It creates:
    /// 1. Symbolic MleAst chunks in G1_CHUNK_STORE (for Fiat-Shamir transcript tunneling)
    /// 2. A G1Op::Var entry in G1_OP_ARENA (for curve operation recording)
    /// 3. Affine (X, Y) coordinate witness values for the gnark circuit
    ///
    /// Use this for BlindFold proof G1 points that participate in both
    /// transcript operations AND curve arithmetic.
    pub fn alloc_g1_var(
        &mut self,
        point: &impl CanonicalSerialize,
        prefix: &str,
    ) -> AstGroupElement {
        // Phase 2: Fiat-Shamir chunk allocation
        let chunks = g1_compressed_to_field_chunks(point);
        let symbolic_chunks = self.alloc_n_with_values(&chunks, prefix);
        let chunk_store_idx = store_g1_chunks(symbolic_chunks);

        // Phase 3: G1 operation variable allocation
        let g1_op_id = zklean_extractor::alloc_g1_op(zklean_extractor::G1Op::Var(
            prefix.to_string(),
        ));

        // Extract affine (X, Y) coordinates for G1 witness
        let (x, y) = extract_g1_affine_coords(point);
        self.g1_witness_coords
            .push((prefix.to_string(), x, y));

        AstGroupElement::new_full(chunk_store_idx, g1_op_id)
    }

    /// Allocate a G1 point variable with G1 operation recording only (no Fiat-Shamir chunks).
    ///
    /// Use this for BlindFold proof G1 points that participate in curve arithmetic
    /// but are NOT appended to the transcript (e.g., intermediate commitments).
    pub fn alloc_g1_var_no_transcript(
        &mut self,
        point: &impl CanonicalSerialize,
        prefix: &str,
    ) -> AstGroupElement {
        let g1_op_id = zklean_extractor::alloc_g1_op(zklean_extractor::G1Op::Var(
            prefix.to_string(),
        ));

        // Extract affine (X, Y) coordinates for G1 witness
        let (x, y) = extract_g1_affine_coords(point);
        self.g1_witness_coords
            .push((prefix.to_string(), x, y));

        AstGroupElement::from_g1_op(g1_op_id)
    }
}

impl Default for VarAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Number of bytes per chunk (one BN254 field element)
const BYTES_PER_CHUNK: usize = 32;

/// Serialize a commitment to bytes in the format used by Poseidon transcript.
/// MUST match the Poseidon transcript serialization exactly:
/// 1. Use serialize_uncompressed (not compressed)
/// 2. LE bytes directly (no byte reversal needed for circuit)
fn commitment_to_bytes<T: CanonicalSerialize>(commitment: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    commitment
        .serialize_uncompressed(&mut bytes)
        .expect("serialization failed");
    bytes
}

/// Convert commitment bytes to field element chunks.
///
/// The number of chunks is derived from the serialized size:
/// `num_chunks = ceil(serialized_size / 32)`
///
/// This is PCS-agnostic: Dory (384 bytes) produces 12 chunks,
/// other PCS types produce different chunk counts based on their commitment size.
fn commitment_to_field_chunks<T: CanonicalSerialize>(commitment: &T) -> Vec<ark_bn254::Fr> {
    let bytes = commitment_to_bytes(commitment);
    let num_chunks = bytes.len().div_ceil(BYTES_PER_CHUNK);

    (0..num_chunks)
        .map(|i| {
            let start = i * BYTES_PER_CHUNK;
            let end = std::cmp::min(start + BYTES_PER_CHUNK, bytes.len());
            ark_bn254::Fr::from_le_bytes_mod_order(&bytes[start..end])
        })
        .collect()
}

/// Extract affine (X, Y) coordinates from a serializable G1 point.
///
/// Uses `serialize_uncompressed` which gives: X (32 bytes LE) + Y (32 bytes LE) + flags.
/// For Grumpkin points, both coordinates are BN254 Fr elements (the 2-cycle property),
/// so they can be used directly as native circuit variables in gnark.
///
/// Returns (x_decimal, y_decimal) as decimal string representations.
fn extract_g1_affine_coords(point: &impl CanonicalSerialize) -> (String, String) {
    let mut bytes = Vec::new();
    point
        .serialize_uncompressed(&mut bytes)
        .expect("G1 uncompressed serialization failed");

    // arkworks uncompressed format: X (field_size bytes LE) + Y (field_size bytes LE) + flags
    // For 256-bit fields: 32 + 32 + 1 = 65 bytes
    assert!(
        bytes.len() >= 64,
        "G1 uncompressed serialization too short: {} bytes",
        bytes.len()
    );

    let x = ark_bn254::Fr::from_le_bytes_mod_order(&bytes[..32]);
    let y = ark_bn254::Fr::from_le_bytes_mod_order(&bytes[32..64]);

    (format!("{}", x.into_bigint()), format!("{}", y.into_bigint()))
}

/// Serialize a G1 point compressed and convert to field element chunks.
///
/// BN254 G1 compressed = 33 bytes → 2 chunks (32 + 1 padded to 32).
/// Uses `serialize_compressed` to match `append_commitment` in the transcript.
fn g1_compressed_to_field_chunks(point: &impl CanonicalSerialize) -> Vec<ark_bn254::Fr> {
    let mut bytes = Vec::new();
    point
        .serialize_compressed(&mut bytes)
        .expect("G1 compressed serialization failed");
    let num_chunks = bytes.len().div_ceil(BYTES_PER_CHUNK);

    (0..num_chunks)
        .map(|i| {
            let start = i * BYTES_PER_CHUNK;
            let end = std::cmp::min(start + BYTES_PER_CHUNK, bytes.len());
            ark_bn254::Fr::from_le_bytes_mod_order(&bytes[start..end])
        })
        .collect()
}

/// Convert a real proof to a symbolic proof for transpilation.
///
/// This is the main entry point for proof symbolization. It creates symbolic
/// variables for every field element in the proof structure.
///
/// # Variable Naming Convention
///
/// Variables are named by their semantic role in the proof:
/// - `commitment_{n}_{chunk}` - Chunk (0-11) of commitment n
/// - `claim_{key:?}` - Opening claim for polynomial key
/// - `stage{n}_uni_skip_coeff_{i}` - Uni-skip polynomial coefficient i
/// - `stage{n}_sumcheck_r{round}_{coeff}` - Sumcheck round polynomial coefficient
/// - `untrusted_advice_commitment_{chunk}` - Advice commitment chunk (if present)
///
/// These names appear in the witness JSON and are transformed by `sanitize_go_name`
/// for Go struct field names.
///
/// # Returns
///
/// - `JoltProof<MleAst>`: The symbolic proof with variables instead of concrete values
/// - `AstOpeningAccumulator`: Accumulator pre-populated with symbolic opening claims
/// - `VarAllocator`: Tracks all allocated variables and their descriptions
///
/// # Type Parameter
///
/// `OutputTranscript` specifies the transcript type for the symbolic proof.
/// Use `PoseidonAstTranscript` for Poseidon-based proofs (current default).
pub fn symbolize_proof<OutputTranscript: Transcript>(
    real_proof: &RV64IMACProof,
) -> (
    JoltProof<MleAst, AstCurve, AstCommitmentScheme, OutputTranscript>,
    AstOpeningAccumulator,
    VarAllocator,
) {
    let mut alloc = VarAllocator::new();

    // === Symbolize commitments (with witness values) ===
    let commitments: Vec<AstCommitment> = real_proof
        .commitments
        .iter()
        .enumerate()
        .map(|(c, commitment)| {
            let chunks = alloc.alloc_commitment(commitment, &format!("commitment_{c}"));
            AstCommitment::new(chunks)
        })
        .collect();

    // === Symbolize opening claims (non-ZK only) ===
    // In ZK mode, opening claims are verified by BlindFold, not pre-populated.
    #[cfg(not(feature = "zk"))]
    let symbolic_claims = {
        let mut claims = BTreeMap::new();
        for (key, (_point, claim)) in &real_proof.opening_claims.0 {
            let symbolic_claim = alloc.alloc_with_value(&format!("claim_{key:?}"), claim);
            claims.insert(*key, (OpeningPoint::default(), symbolic_claim));
        }
        claims
    };

    // === Symbolize stage 1 uni-skip proof ===
    let stage1_uni_skip = symbolize_uni_skip_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage1_uni_skip_first_round_proof,
        &mut alloc,
        "stage1_uni_skip",
    );

    // === Symbolize stage 1 sumcheck proof ===
    let stage1_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage1_sumcheck_proof,
        &mut alloc,
        "stage1_sumcheck",
    );

    // === Symbolize stage 2 uni-skip proof ===
    let stage2_uni_skip = symbolize_uni_skip_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage2_uni_skip_first_round_proof,
        &mut alloc,
        "stage2_uni_skip",
    );

    // === Symbolize stage 2 sumcheck proof ===
    let stage2_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage2_sumcheck_proof,
        &mut alloc,
        "stage2_sumcheck",
    );

    // === Symbolize stage 3 sumcheck proof ===
    let stage3_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage3_sumcheck_proof,
        &mut alloc,
        "stage3_sumcheck",
    );

    // === Symbolize stage 4 sumcheck proof ===
    let stage4_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage4_sumcheck_proof,
        &mut alloc,
        "stage4_sumcheck",
    );

    // === Symbolize stage 5 sumcheck proof ===
    let stage5_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage5_sumcheck_proof,
        &mut alloc,
        "stage5_sumcheck",
    );

    // === Symbolize stage 6 sumcheck proof ===
    let stage6_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage6_sumcheck_proof,
        &mut alloc,
        "stage6_sumcheck",
    );

    // === Symbolize stage 7 sumcheck proof ===
    let stage7_sumcheck = symbolize_sumcheck_variant::<PedersenCurve, _, OutputTranscript>(
        &real_proof.stage7_sumcheck_proof,
        &mut alloc,
        "stage7_sumcheck",
    );

    // === Symbolize advice commitment (if present, with witness values) ===
    let untrusted_advice_commitment =
        real_proof
            .untrusted_advice_commitment
            .as_ref()
            .map(|commitment| {
                let chunks = alloc.alloc_commitment(commitment, "untrusted_advice_commitment");
                AstCommitment::new(chunks)
            });

    // Build the symbolic proof
    let symbolic_proof = JoltProof {
        #[cfg(not(feature = "zk"))]
        opening_claims: Claims(symbolic_claims),
        #[cfg(feature = "zk")]
        blindfold_proof: symbolize_blindfold_proof(&real_proof.blindfold_proof, &mut alloc),
        commitments,
        stage1_uni_skip_first_round_proof: stage1_uni_skip,
        stage1_sumcheck_proof: stage1_sumcheck,
        stage2_uni_skip_first_round_proof: stage2_uni_skip,
        stage2_sumcheck_proof: stage2_sumcheck,
        stage3_sumcheck_proof: stage3_sumcheck,
        stage4_sumcheck_proof: stage4_sumcheck,
        stage5_sumcheck_proof: stage5_sumcheck,
        stage6_sumcheck_proof: stage6_sumcheck,
        stage7_sumcheck_proof: stage7_sumcheck,
        joint_opening_proof: AstProof::default(),
        untrusted_advice_commitment,
        trace_length: real_proof.trace_length,
        ram_K: real_proof.ram_K,
        rw_config: real_proof.rw_config.clone(),
        one_hot_config: real_proof.one_hot_config.clone(),
        dory_layout: real_proof.dory_layout,
    };

    // In ZK mode, extract the eval commitment (y_com) from the real proof
    // and register it as a symbolic G1 variable for BlindFold verification.
    #[cfg(feature = "zk")]
    {
        use jolt_core::poly::commitment::commitment_scheme::ZkEvalCommitment;
        use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
        if let Some(y_com) =
            <DoryCommitmentScheme as ZkEvalCommitment<PedersenCurve>>::eval_commitment(
                &real_proof.joint_opening_proof,
            )
        {
            let ast_y_com = alloc.alloc_g1_var(&y_com, "eval_commitment");
            crate::symbolic_traits::ast_commitment_scheme::set_eval_commitment_op_id(
                ast_y_com.g1_op_id(),
            );
        }
    }

    // Build the opening accumulator
    #[allow(non_snake_case)]
    let log_T = (real_proof.trace_length as f64).log2().ceil() as usize;
    let mut accumulator = AstOpeningAccumulator::new(log_T);

    // In non-ZK mode, pre-populate with symbolic opening claims.
    // In ZK mode, claims are verified by BlindFold — accumulator runs in zk_mode.
    #[cfg(not(feature = "zk"))]
    for (key, (_, claim)) in &symbolic_proof.opening_claims.0 {
        accumulator.openings.insert(*key, (vec![], *claim));
    }
    #[cfg(feature = "zk")]
    {
        accumulator.zk_mode = true;
    }

    (symbolic_proof, accumulator, alloc)
}

// =============================================================================
// Symbolization Helpers
// =============================================================================
//
// These functions convert concrete proof components (Fr values) to symbolic form
// (MleAst variables) while simultaneously recording witness values in VarAllocator.

/// Symbolize a UniSkipFirstRoundProofVariant by extracting the Standard inner proof,
/// converting its polynomial coefficients to symbolic variables, and re-wrapping.
fn symbolize_uni_skip_variant<C: JoltCurve, T: Transcript, OutT: Transcript>(
    real: &UniSkipFirstRoundProofVariant<ark_bn254::Fr, C, T>,
    alloc: &mut VarAllocator,
    prefix: &str,
) -> UniSkipFirstRoundProofVariant<MleAst, AstCurve, OutT> {
    match real {
        UniSkipFirstRoundProofVariant::Standard(inner) => {
            let coeffs =
                alloc.alloc_n_with_values(&inner.uni_poly.coeffs, &format!("{prefix}_coeff"));
            UniSkipFirstRoundProofVariant::Standard(UniSkipFirstRoundProof::new(
                jolt_core::poly::unipoly::UniPoly::from_coeff(coeffs),
            ))
        }
        UniSkipFirstRoundProofVariant::Zk(inner) => {
            let commitment =
                alloc.alloc_g1_var(&inner.commitment, &format!("{prefix}_commit"));
            let output_claims_commitment = alloc.alloc_g1_var(
                &inner.output_claims_commitment,
                &format!("{prefix}_output_commit"),
            );
            UniSkipFirstRoundProofVariant::Zk(ZkUniSkipFirstRoundProof::new(
                commitment,
                inner.poly_degree,
                output_claims_commitment,
            ))
        }
    }
}

/// Symbolize a SumcheckInstanceProof by extracting the Clear inner proof,
/// converting its compressed polynomial coefficients to symbolic variables,
/// and re-wrapping.
fn symbolize_sumcheck_variant<C: JoltCurve, T: Transcript, OutT: Transcript>(
    real: &SumcheckInstanceProof<ark_bn254::Fr, C, T>,
    alloc: &mut VarAllocator,
    prefix: &str,
) -> SumcheckInstanceProof<MleAst, AstCurve, OutT> {
    match real {
        SumcheckInstanceProof::Clear(clear_proof) => {
            let compressed_polys: Vec<CompressedUniPoly<MleAst>> = clear_proof
                .compressed_polys
                .iter()
                .enumerate()
                .map(|(round, poly)| {
                    let coeffs = alloc.alloc_n_with_values(
                        &poly.coeffs_except_linear_term,
                        &format!("{prefix}_r{round}"),
                    );
                    CompressedUniPoly {
                        coeffs_except_linear_term: coeffs,
                    }
                })
                .collect();

            SumcheckInstanceProof::new_standard(compressed_polys)
        }
        SumcheckInstanceProof::Zk(zk_proof) => {
            let round_commitments: Vec<_> = zk_proof
                .round_commitments
                .iter()
                .enumerate()
                .map(|(round, g1)| {
                    alloc.alloc_g1_var(g1, &format!("{prefix}_r{round}_commit"))
                })
                .collect();
            let output_claims_commitment = alloc.alloc_g1_var(
                &zk_proof.output_claims_commitment,
                &format!("{prefix}_output_commit"),
            );
            SumcheckInstanceProof::Zk(ZkSumcheckProof::new(
                round_commitments,
                zk_proof.poly_degrees.clone(),
                output_claims_commitment,
            ))
        }
    }
}

/// Symbolize a concrete BlindFoldProof into symbolic form.
///
/// Converts all G1 points to `AstGroupElement` (with G1 operation recording)
/// and all field elements to symbolic `MleAst` variables.
///
/// This enables `BlindFoldVerifier::verify()` to run symbolically, recording
/// all curve and field operations for gnark code generation.
#[cfg(feature = "zk")]
fn symbolize_blindfold_proof<C: jolt_core::curve::JoltCurve>(
    real_proof: &BlindFoldProof<ark_bn254::Fr, C>,
    alloc: &mut VarAllocator,
) -> BlindFoldProof<MleAst, AstCurve>
where
    C::G1: CanonicalSerialize,
{
    use jolt_core::poly::commitment::hyrax::HyraxOpeningProof;

    // Helper: symbolize a Vec<G1> with indexed names
    let sym_g1_vec = |points: &[C::G1],
                      prefix: &str,
                      alloc: &mut VarAllocator|
     -> Vec<AstGroupElement> {
        points
            .iter()
            .enumerate()
            .map(|(i, g1)| alloc.alloc_g1_var(g1, &format!("{prefix}_{i}")))
            .collect()
    };

    // === Symbolize random_instance (RelaxedR1CSInstance) ===
    let random_instance = RelaxedR1CSInstance {
        u: alloc.alloc_with_value("bf_random_u", &real_proof.random_instance.u),
        round_commitments: sym_g1_vec(
            &real_proof.random_instance.round_commitments,
            "bf_random_round_commit",
            alloc,
        ),
        noncoeff_row_commitments: sym_g1_vec(
            &real_proof.random_instance.noncoeff_row_commitments,
            "bf_random_noncoeff_row",
            alloc,
        ),
        e_row_commitments: sym_g1_vec(
            &real_proof.random_instance.e_row_commitments,
            "bf_random_e_row",
            alloc,
        ),
        eval_commitments: sym_g1_vec(
            &real_proof.random_instance.eval_commitments,
            "bf_random_eval_commit",
            alloc,
        ),
    };

    // === Symbolize G1 commitment vectors ===
    let noncoeff_row_commitments = sym_g1_vec(
        &real_proof.noncoeff_row_commitments,
        "bf_noncoeff_row",
        alloc,
    );
    let cross_term_row_commitments = sym_g1_vec(
        &real_proof.cross_term_row_commitments,
        "bf_cross_term_row",
        alloc,
    );

    // === Symbolize Spartan outer sumcheck (CompressedUniPoly coefficients) ===
    let spartan_proof: Vec<CompressedUniPoly<MleAst>> = real_proof
        .spartan_proof
        .iter()
        .enumerate()
        .map(|(round, poly)| CompressedUniPoly {
            coeffs_except_linear_term: alloc.alloc_n_with_values(
                &poly.coeffs_except_linear_term,
                &format!("bf_spartan_r{round}"),
            ),
        })
        .collect();

    // === Symbolize field scalars ===
    let az_r = alloc.alloc_with_value("bf_az_r", &real_proof.az_r);
    let bz_r = alloc.alloc_with_value("bf_bz_r", &real_proof.bz_r);
    let cz_r = alloc.alloc_with_value("bf_cz_r", &real_proof.cz_r);

    // === Symbolize inner sumcheck proof ===
    let inner_sumcheck_proof: Vec<CompressedUniPoly<MleAst>> = real_proof
        .inner_sumcheck_proof
        .iter()
        .enumerate()
        .map(|(round, poly)| CompressedUniPoly {
            coeffs_except_linear_term: alloc.alloc_n_with_values(
                &poly.coeffs_except_linear_term,
                &format!("bf_inner_r{round}"),
            ),
        })
        .collect();

    // === Symbolize Hyrax opening proofs ===
    let w_opening = HyraxOpeningProof {
        combined_row: alloc.alloc_n_with_values(
            &real_proof.w_opening.combined_row,
            "bf_w_opening_row",
        ),
        combined_blinding: alloc.alloc_with_value(
            "bf_w_opening_blinding",
            &real_proof.w_opening.combined_blinding,
        ),
    };
    let e_opening = HyraxOpeningProof {
        combined_row: alloc.alloc_n_with_values(
            &real_proof.e_opening.combined_row,
            "bf_e_opening_row",
        ),
        combined_blinding: alloc.alloc_with_value(
            "bf_e_opening_blinding",
            &real_proof.e_opening.combined_blinding,
        ),
    };

    // === Symbolize folded eval outputs and blindings ===
    let folded_eval_outputs = alloc.alloc_n_with_values(
        &real_proof.folded_eval_outputs,
        "bf_folded_eval_out",
    );
    let folded_eval_blindings = alloc.alloc_n_with_values(
        &real_proof.folded_eval_blindings,
        "bf_folded_eval_blind",
    );

    BlindFoldProof {
        random_instance,
        noncoeff_row_commitments,
        cross_term_row_commitments,
        spartan_proof,
        az_r,
        bz_r,
        cz_r,
        inner_sumcheck_proof,
        w_opening,
        e_opening,
        folded_eval_outputs,
        folded_eval_blindings,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use zklean_extractor::mle_ast::{get_node, Atom, Node};

    // =========================================================================
    // VarAllocator Tests
    // =========================================================================

    #[test]
    fn test_var_allocator_index_increments() {
        // Each allocation must get a unique, incrementing index
        let mut alloc = VarAllocator::new();
        assert_eq!(alloc.next_idx(), 0);

        let var0 = alloc.alloc_with_value("v0", &Fr::from(100u64));
        assert_eq!(alloc.next_idx(), 1);

        let var1 = alloc.alloc_with_value("v1", &Fr::from(200u64));
        assert_eq!(alloc.next_idx(), 2);

        // Verify variables have different indices
        assert!(matches!(get_node(var0.root()), Node::Atom(Atom::Var(0))));
        assert!(matches!(get_node(var1.root()), Node::Atom(Atom::Var(1))));
    }

    #[test]
    fn test_var_allocator_witness_index_sync() {
        // CRITICAL: witness_values[i] MUST correspond to Var(i)
        // This is the core invariant - if this breaks, witness loading fails
        let mut alloc = VarAllocator::new();

        let val0 = Fr::from(111u64);
        let val1 = Fr::from(222u64);
        let val2 = Fr::from(333u64);

        let var0 = alloc.alloc_with_value("v0", &val0);
        let var1 = alloc.alloc_with_value("v1", &val1);
        let var2 = alloc.alloc_with_value("v2", &val2);

        let witness = alloc.witness_values();

        // Extract variable indices from MleAst nodes
        let idx0 = match get_node(var0.root()) {
            Node::Atom(Atom::Var(i)) => i,
            _ => panic!("Expected Var node"),
        };
        let idx1 = match get_node(var1.root()) {
            Node::Atom(Atom::Var(i)) => i,
            _ => panic!("Expected Var node"),
        };
        let idx2 = match get_node(var2.root()) {
            Node::Atom(Atom::Var(i)) => i,
            _ => panic!("Expected Var node"),
        };

        // CRITICAL: witness[idx] MUST match the value allocated with Var(idx)
        assert_eq!(
            witness.get(&(idx0 as usize)).unwrap(),
            &format!("{}", val0.into_bigint())
        );
        assert_eq!(
            witness.get(&(idx1 as usize)).unwrap(),
            &format!("{}", val1.into_bigint())
        );
        assert_eq!(
            witness.get(&(idx2 as usize)).unwrap(),
            &format!("{}", val2.into_bigint())
        );
    }

    #[test]
    fn test_var_allocator_field_type_fr() {
        // Verify Fr (native) field type tracking
        let mut alloc = VarAllocator::new();
        alloc.alloc_with_value_and_field("fr_var", &Fr::from(123u64), TargetField::Fr);

        assert!(alloc.has_variables_for_field(TargetField::Fr));
        assert!(!alloc.has_variables_for_field(TargetField::Fq));

        let descriptions = alloc.descriptions_with_fields();
        assert_eq!(descriptions[0].2, TargetField::Fr);
    }

    #[test]
    fn test_var_allocator_field_type_non_native() {
        // Verify non-native field type tracking (Fq in this case, but could be any non-Fr field)
        let mut alloc = VarAllocator::new();
        alloc.alloc_with_value_and_field("non_native_var", &Fr::from(456u64), TargetField::Fq);

        assert!(alloc.has_variables_for_field(TargetField::Fq));
        assert!(!alloc.has_variables_for_field(TargetField::Fr));

        let descriptions = alloc.descriptions_with_fields();
        assert_eq!(descriptions[0].2, TargetField::Fq);
    }

    #[test]
    fn test_var_allocator_has_variables_for_field() {
        // Verify field query works with mixed allocations (native + non-native)
        let mut alloc = VarAllocator::new();

        alloc.alloc_with_value("fr_default", &Fr::from(10u64)); // Default = Fr (native)
        alloc.alloc_with_value_and_field("non_native_explicit", &Fr::from(20u64), TargetField::Fq);

        assert!(alloc.has_variables_for_field(TargetField::Fr));
        assert!(alloc.has_variables_for_field(TargetField::Fq));
    }

    #[test]
    fn test_alloc_n_with_values() {
        // Test batch allocation with alloc_n_with_values
        let mut alloc = VarAllocator::new();

        let values = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let vars = alloc.alloc_n_with_values(&values, "batch");

        // Verify correct number of variables allocated
        assert_eq!(vars.len(), 3);
        assert_eq!(alloc.next_idx(), 3);

        // Verify each variable has correct index
        for (i, var) in vars.iter().enumerate() {
            assert!(matches!(
                get_node(var.root()),
                Node::Atom(Atom::Var(idx)) if idx as usize == i
            ));
        }

        // Verify witness values
        let witness = alloc.witness_values();
        for (i, val) in values.iter().enumerate() {
            assert_eq!(witness.get(&i).unwrap(), &format!("{}", val.into_bigint()));
        }

        // Verify descriptions
        let descriptions = alloc.descriptions_with_fields();
        assert_eq!(descriptions[0].1, "batch_0");
        assert_eq!(descriptions[1].1, "batch_1");
        assert_eq!(descriptions[2].1, "batch_2");

        // Verify all have Fr field type (default)
        for (_, _, field) in descriptions {
            assert_eq!(*field, TargetField::Fr);
        }
    }

    #[test]
    fn test_alloc_commitment() {
        // Test alloc_commitment produces correct number of variables
        use ark_bn254::G1Affine;
        use ark_std::UniformRand;

        let mut alloc = VarAllocator::new();
        let mut rng = ark_std::test_rng();
        let point = G1Affine::rand(&mut rng);

        let vars = alloc.alloc_commitment(&point, "commitment");

        // Verify number of variables matches chunking
        let chunks = commitment_to_field_chunks(&point);
        assert_eq!(vars.len(), chunks.len());

        // Verify indices are sequential
        for (i, var) in vars.iter().enumerate() {
            assert!(matches!(
                get_node(var.root()),
                Node::Atom(Atom::Var(idx)) if idx as usize == i
            ));
        }

        // Verify witness values match chunks
        let witness = alloc.witness_values();
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(
                witness.get(&i).unwrap(),
                &format!("{}", chunk.into_bigint())
            );
        }

        // Verify descriptions
        let descriptions = alloc.descriptions_with_fields();
        assert_eq!(descriptions[0].1, "commitment_0");
        assert!(descriptions.len() == chunks.len());
    }

    // =========================================================================
    // Commitment Chunking Tests
    // =========================================================================

    #[test]
    fn test_commitment_to_field_chunks_g1() {
        // Verify G1Affine commitment produces correct number of chunks
        use ark_bn254::G1Affine;
        use ark_std::UniformRand;

        let mut rng = ark_std::test_rng();
        let point = G1Affine::rand(&mut rng);

        let chunks = commitment_to_field_chunks(&point);
        let bytes = commitment_to_bytes(&point);

        // Verify chunk count matches ceil(bytes.len() / 32)
        let expected_chunks = bytes.len().div_ceil(BYTES_PER_CHUNK);
        assert_eq!(
            chunks.len(),
            expected_chunks,
            "G1Affine ({} bytes) should produce {} chunks",
            bytes.len(),
            expected_chunks
        );

        // Verify chunks are non-trivial (random point → non-zero chunks)
        for (i, chunk) in chunks.iter().enumerate() {
            assert_ne!(
                *chunk,
                Fr::from(0u64),
                "Chunk {i} should not be zero for random point"
            );
        }
    }

    #[test]
    fn test_commitment_chunking_matches_poseidon() {
        // CRITICAL: Verify chunk values match what Poseidon transcript expects
        // This ensures commitment_to_field_chunks produces identical chunks
        // to what Poseidon transcript uses when hashing commitments
        use ark_bn254::G1Affine;
        use ark_std::UniformRand;

        let mut rng = ark_std::test_rng();
        let point = G1Affine::rand(&mut rng);

        let chunks = commitment_to_field_chunks(&point);
        let bytes = commitment_to_bytes(&point);

        // Verify each chunk matches its byte slice
        for (i, chunk) in chunks.iter().enumerate() {
            let start = i * BYTES_PER_CHUNK;
            let end = std::cmp::min(start + BYTES_PER_CHUNK, bytes.len());
            let expected_chunk = Fr::from_le_bytes_mod_order(&bytes[start..end]);

            assert_eq!(
                *chunk, expected_chunk,
                "Chunk {i} should match bytes[{start}..{end}] (Poseidon format)"
            );
        }
    }
}
