//! `JoltCurve` implementation for symbolic transpilation with G1 operation recording.
//!
//! This module provides `AstCurve` which satisfies `JoltCurve` bounds and records
//! G1 curve operations symbolically for BlindFold transpilation.
//!
//! ## Two roles for AstGroupElement:
//!
//! 1. **Fiat-Shamir tunneling** (Phase 2): `chunk_store_idx` indexes into G1_CHUNK_STORE,
//!    enabling `serialize_compressed` to tunnel symbolic MleAst chunks to
//!    `PoseidonAstTranscript::append_commitment`.
//!
//! 2. **G1 operation recording** (Phase 3): `g1_op_id` indexes into G1_OP_ARENA,
//!    recording curve operations (scalar_mul, add, MSM) for gnark codegen.

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Valid, Write,
};
use jolt_core::curve::{Bn254G1, JoltCurve, JoltGroupElement};
use jolt_core::field::JoltField;
use std::cell::RefCell;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use zklean_extractor::mle_ast::MleAst;
use zklean_extractor::{
    alloc_g1_op, get_g1_chunks, is_constraint_mode, register_g1_constraint, set_pending_g1_chunks,
    G1Op, G1OpId, G1_OP_NONE,
};

thread_local! {
    /// Captures G1 affine coordinates from `From<Bn254G1>` conversions.
    /// Each entry: (name, x_decimal, y_decimal) for witness JSON.
    /// Used for Pedersen generators and eval commitment generators that are
    /// converted to AstGroupElement during symbolic execution.
    static G1_FROM_WITNESSES: RefCell<Vec<(String, String, String)>> = RefCell::new(Vec::new());
}

/// Drain the captured G1 coordinate witnesses from `From<Bn254G1>` conversions.
pub fn take_g1_from_witnesses() -> Vec<(String, String, String)> {
    G1_FROM_WITNESSES.with(|w| w.borrow_mut().drain(..).collect())
}

/// Symbolic group element that records G1 operations for transpilation.
///
/// Both `chunk_store_idx` and `g1_op_id` may be active simultaneously:
/// - `chunk_store_idx` is used for Fiat-Shamir transcript operations
/// - `g1_op_id` is used for G1 arithmetic recording
#[derive(Clone, Copy, Debug)]
pub struct AstGroupElement {
    /// Index into G1_CHUNK_STORE for Fiat-Shamir tunneling.
    /// `u32::MAX` = sentinel for "no chunks" (default/zero).
    chunk_store_idx: u32,
    /// Index into G1_OP_ARENA for curve operation recording.
    /// `G1_OP_NONE` (u32::MAX) = sentinel for "no operation" (uninitialized).
    g1_op_id: G1OpId,
}

/// Counter for auto-naming G1 equality constraints.
static G1_CONSTRAINT_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Counter for auto-naming G1 points created from Bn254G1 conversions (e.g., Pedersen generators).
static G1_FROM_BN254_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Reset the Bn254G1 conversion counter (call before symbolic execution).
pub fn reset_g1_from_counter() {
    G1_FROM_BN254_COUNTER.store(0, std::sync::atomic::Ordering::Relaxed);
}

impl From<Bn254G1> for AstGroupElement {
    /// Convert a concrete Bn254G1 point to a symbolic G1 variable.
    ///
    /// Used by `JoltVerifierPreprocessing::pedersen_generators::<C>()` to convert
    /// stored BN254 generators to `AstGroupElement` for symbolic BlindFold execution.
    /// Each converted point gets a unique `G1Op::Var("PedersenGen_N")` name.
    ///
    /// Also extracts the Grumpkin affine coordinates (via Bn254G1→GrumpkinG1 conversion)
    /// and stores them as witness values for gnark circuit generation.
    fn from(#[allow(unused_variables)] bn254_point: Bn254G1) -> Self {
        let idx = G1_FROM_BN254_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[allow(unused_variables)]
        let name = format!("PedersenGen_{idx}");
        let op_id = alloc_g1_op(G1Op::Var(name.clone()));

        // Convert Bn254G1 → GrumpkinG1 (hash-to-curve) and extract affine coordinates.
        // Grumpkin base field = BN254 scalar field (Fr), so coordinates are native.
        #[cfg(feature = "zk")]
        {
            use ark_ff::PrimeField;
            let grumpkin_point = jolt_core::curve::GrumpkinG1::from(bn254_point);
            let mut bytes = Vec::new();
            grumpkin_point
                .serialize_uncompressed(&mut bytes)
                .expect("GrumpkinG1 uncompressed serialization failed");
            let x = ark_bn254::Fr::from_le_bytes_mod_order(&bytes[..32]);
            let y = ark_bn254::Fr::from_le_bytes_mod_order(&bytes[32..64]);
            let x_dec = format!("{}", x.into_bigint());
            let y_dec = format!("{}", y.into_bigint());
            G1_FROM_WITNESSES.with(|w| w.borrow_mut().push((name, x_dec, y_dec)));
        }

        Self::from_g1_op(op_id)
    }
}

impl AstGroupElement {
    /// Create an AstGroupElement with both chunk store and G1 op indices.
    pub fn new_full(chunk_store_idx: u32, g1_op_id: G1OpId) -> Self {
        Self {
            chunk_store_idx,
            g1_op_id,
        }
    }

    /// Create an AstGroupElement backed by symbolic chunks only (Phase 2 compatibility).
    pub fn new(chunk_store_idx: u32) -> Self {
        Self {
            chunk_store_idx,
            g1_op_id: G1_OP_NONE,
        }
    }

    /// Create an AstGroupElement with only a G1 operation (no Fiat-Shamir chunks).
    pub fn from_g1_op(g1_op_id: G1OpId) -> Self {
        Self {
            chunk_store_idx: u32::MAX,
            g1_op_id,
        }
    }

    /// Get the G1 operation ID.
    pub fn g1_op_id(&self) -> G1OpId {
        self.g1_op_id
    }
}

/// Extract NodeId from a JoltField value by downcasting to MleAst.
///
/// During symbolic execution, all field values are MleAst. This function
/// uses `Any` downcasting to extract the root NodeId from the symbolic value.
///
/// # Panics
/// Panics if `scalar` is not an `MleAst` (should never happen during symbolic execution).
fn extract_node_id<F: JoltField>(scalar: &F) -> usize {
    use std::any::Any;
    let scalar_any: &dyn Any = scalar;
    scalar_any
        .downcast_ref::<MleAst>()
        .expect("scalar_mul called with non-MleAst type during symbolic execution")
        .root()
}

impl Default for AstGroupElement {
    fn default() -> Self {
        Self {
            chunk_store_idx: u32::MAX,
            g1_op_id: G1_OP_NONE,
        }
    }
}

impl Eq for AstGroupElement {}

impl PartialEq for AstGroupElement {
    fn eq(&self, other: &Self) -> bool {
        if is_constraint_mode()
            && self.g1_op_id != G1_OP_NONE
            && other.g1_op_id != G1_OP_NONE
        {
            // In constraint mode, register a G1 equality constraint
            let idx = G1_CONSTRAINT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            register_g1_constraint(
                format!("g1_eq_{idx}"),
                self.g1_op_id,
                other.g1_op_id,
            );
            true // Allow symbolic execution to continue
        } else {
            // Outside constraint mode, compare structurally
            self.chunk_store_idx == other.chunk_store_idx && self.g1_op_id == other.g1_op_id
        }
    }
}

// ---------------------------------------------------------------------------
// Arithmetic operator implementations — record G1 operations in the arena
// ---------------------------------------------------------------------------

impl Add for AstGroupElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let op_id = alloc_g1_op(G1Op::Add(self.g1_op_id, rhs.g1_op_id));
        Self::from_g1_op(op_id)
    }
}

impl<'a> Add<&'a AstGroupElement> for AstGroupElement {
    type Output = Self;
    fn add(self, rhs: &'a AstGroupElement) -> Self {
        let op_id = alloc_g1_op(G1Op::Add(self.g1_op_id, rhs.g1_op_id));
        Self::from_g1_op(op_id)
    }
}

impl Sub for AstGroupElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let op_id = alloc_g1_op(G1Op::Sub(self.g1_op_id, rhs.g1_op_id));
        Self::from_g1_op(op_id)
    }
}

impl<'a> Sub<&'a AstGroupElement> for AstGroupElement {
    type Output = Self;
    fn sub(self, rhs: &'a AstGroupElement) -> Self {
        let op_id = alloc_g1_op(G1Op::Sub(self.g1_op_id, rhs.g1_op_id));
        Self::from_g1_op(op_id)
    }
}

impl Neg for AstGroupElement {
    type Output = Self;
    fn neg(self) -> Self {
        let op_id = alloc_g1_op(G1Op::Neg(self.g1_op_id));
        Self::from_g1_op(op_id)
    }
}

impl AddAssign for AstGroupElement {
    fn add_assign(&mut self, rhs: Self) {
        let op_id = alloc_g1_op(G1Op::Add(self.g1_op_id, rhs.g1_op_id));
        self.g1_op_id = op_id;
        self.chunk_store_idx = u32::MAX; // Result has no pre-stored chunks
    }
}

impl SubAssign for AstGroupElement {
    fn sub_assign(&mut self, rhs: Self) {
        let op_id = alloc_g1_op(G1Op::Sub(self.g1_op_id, rhs.g1_op_id));
        self.g1_op_id = op_id;
        self.chunk_store_idx = u32::MAX;
    }
}

// ---------------------------------------------------------------------------
// Serialization (unchanged from Phase 2 — Fiat-Shamir tunneling)
// ---------------------------------------------------------------------------

impl Valid for AstGroupElement {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for AstGroupElement {
    fn serialize_with_mode<W: Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        if self.chunk_store_idx != u32::MAX {
            let chunks = get_g1_chunks(self.chunk_store_idx);
            set_pending_g1_chunks(chunks);
        }
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        0
    }
}

impl CanonicalDeserialize for AstGroupElement {
    fn deserialize_with_mode<R: Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self::default())
    }
}

// ---------------------------------------------------------------------------
// JoltGroupElement — records operations in G1_OP_ARENA
// ---------------------------------------------------------------------------

impl JoltGroupElement for AstGroupElement {
    fn zero() -> Self {
        let op_id = alloc_g1_op(G1Op::Zero);
        Self {
            chunk_store_idx: u32::MAX,
            g1_op_id: op_id,
        }
    }

    fn is_zero(&self) -> bool {
        // During symbolic execution, we can't determine if a computed G1 point is zero.
        // Return false conservatively — BlindFold verification doesn't branch on is_zero().
        self.g1_op_id == G1_OP_NONE && self.chunk_store_idx == u32::MAX
    }

    fn double(&self) -> Self {
        let op_id = alloc_g1_op(G1Op::Double(self.g1_op_id));
        Self::from_g1_op(op_id)
    }

    fn scalar_mul<F: JoltField>(&self, scalar: &F) -> Self {
        let node_id = extract_node_id(scalar);
        let op_id = alloc_g1_op(G1Op::ScalarMul(self.g1_op_id, node_id));
        Self::from_g1_op(op_id)
    }
}

// ===========================================================================
// AstGTElement (stub — pairing never used in BlindFold)
// ===========================================================================

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AstGTElement;

impl Add for AstGTElement {
    type Output = Self;
    fn add(self, _rhs: Self) -> Self {
        unimplemented!("AstGTElement::add called during symbolic execution")
    }
}

impl<'a> Add<&'a AstGTElement> for AstGTElement {
    type Output = Self;
    fn add(self, _rhs: &'a AstGTElement) -> Self {
        unimplemented!("AstGTElement::add called during symbolic execution")
    }
}

impl AddAssign for AstGTElement {
    fn add_assign(&mut self, _rhs: Self) {
        unimplemented!("AstGTElement::add_assign called during symbolic execution")
    }
}

impl Valid for AstGTElement {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for AstGTElement {
    fn serialize_with_mode<W: Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        0
    }
}

impl CanonicalDeserialize for AstGTElement {
    fn deserialize_with_mode<R: Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self)
    }
}

// ===========================================================================
// AstCurve — records G1 operations, stubs G2/pairing
// ===========================================================================

/// Symbolic curve for transpilation.
///
/// Records G1 operations in the G1_OP_ARENA for later codegen to `sw_grumpkin`
/// gnark API calls. G2/GT/pairing are stubbed (never used in BlindFold).
#[derive(Clone, Debug, Default)]
pub struct AstCurve;

impl JoltCurve for AstCurve {
    type G1 = AstGroupElement;
    type G2 = AstGroupElement;
    type GT = AstGTElement;

    fn g1_generator() -> Self::G1 {
        // BlindFold never calls g1_generator() — generators come from PedersenGenerators
        unimplemented!("AstCurve::g1_generator called during symbolic execution")
    }

    fn g2_generator() -> Self::G2 {
        unimplemented!("AstCurve::g2_generator called during symbolic execution")
    }

    fn pairing(_g1: &Self::G1, _g2: &Self::G2) -> Self::GT {
        unimplemented!("AstCurve::pairing called during symbolic execution")
    }

    fn multi_pairing(_g1s: &[Self::G1], _g2s: &[Self::G2]) -> Self::GT {
        unimplemented!("AstCurve::multi_pairing called during symbolic execution")
    }

    fn g1_msm<F: JoltField>(bases: &[Self::G1], scalars: &[F]) -> Self::G1 {
        let base_ids: Vec<G1OpId> = bases.iter().map(|b| b.g1_op_id).collect();
        let scalar_ids: Vec<usize> = scalars.iter().map(extract_node_id).collect();
        let op_id = alloc_g1_op(G1Op::MSM(base_ids, scalar_ids));
        AstGroupElement::from_g1_op(op_id)
    }

    fn g2_msm<F: JoltField>(_bases: &[Self::G2], _scalars: &[F]) -> Self::G2 {
        unimplemented!("AstCurve::g2_msm called during symbolic execution")
    }

    fn random_g1<R: rand_core::RngCore>(_rng: &mut R) -> Self::G1 {
        unimplemented!("AstCurve::random_g1 called during symbolic execution")
    }
}
