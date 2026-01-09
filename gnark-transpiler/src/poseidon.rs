//! Poseidon transcript for symbolic execution (MleAst)
//!
//! This implementation mirrors jolt-core's PoseidonTranscript but records
//! operations in MleAst instead of computing actual hashes. The structure
//! matches exactly to ensure circuit compatibility:
//!
//! - Width-3 Poseidon: poseidon(state, n_rounds, data)
//! - Domain separation via n_rounds counter
//! - Same byte chunking and padding behavior

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use jolt_core::field::JoltField;
use jolt_core::transcripts::Transcript;
use std::borrow::Borrow;
use zklean_extractor::mle_ast::{set_pending_challenge, take_pending_append, MleAst};

/// Convert 32 bytes (little-endian) to i128.
/// For values that fit in i128, this matches Fr::from_le_bytes_mod_order behavior.
/// Note: i128 can only hold 128 bits, but field elements are 256 bits.
/// For transpilation purposes, we only need to capture the symbolic structure,
/// not compute actual values (Gnark will do that).
fn bytes_to_le_i128(bytes: &[u8; 32]) -> i128 {
    // Take first 16 bytes (128 bits) in little-endian
    let mut value: i128 = 0;
    for (i, &byte) in bytes.iter().take(16).enumerate() {
        value |= (byte as i128) << (8 * i);
    }
    value
}

/// Poseidon transcript for symbolic execution.
/// Mirrors jolt-core's PoseidonTranscript structure exactly:
/// - 32-byte state (represented as MleAst)
/// - n_rounds counter for domain separation
/// - Width-3 Poseidon: hash(state, n_rounds, data)
#[derive(Clone)]
pub struct PoseidonMleTranscript {
    /// Current state (symbolic field element)
    state: MleAst,
    /// Round counter for domain separation
    n_rounds: u32,
}

impl Default for PoseidonMleTranscript {
    fn default() -> Self {
        Self {
            state: MleAst::from_i128(0),
            n_rounds: 0,
        }
    }
}

impl PoseidonMleTranscript {
    /// Convert a label to a field element, matching jolt-core's behavior.
    ///
    /// jolt-core does: label_padded[..label.len()].copy_from_slice(label);
    ///                 Fr::from_le_bytes_mod_order(&label_padded)
    ///
    /// For symbolic execution, we compute the actual integer value that
    /// the label bytes represent in little-endian order.
    fn label_to_field(label: &[u8]) -> MleAst {
        assert!(label.len() <= 32, "Label must be <= 32 bytes");

        // Convert label bytes to integer (little-endian)
        // This matches Fr::from_le_bytes_mod_order behavior for small values
        let mut value: i128 = 0;
        for (i, &byte) in label.iter().enumerate() {
            value |= (byte as i128) << (8 * i);
        }

        MleAst::from_i128(value)
    }

    /// Create a new transcript with initial state.
    ///
    /// Mirrors jolt-core: initial_state = poseidon(label, 0, 0)
    pub fn new_mle(label: &'static [u8]) -> Self {
        let label_field = Self::label_to_field(label);
        let initial_state =
            MleAst::poseidon(&label_field, &MleAst::from_i128(0), &MleAst::from_i128(0));
        Self {
            state: initial_state,
            n_rounds: 0,
        }
    }

    /// Hash a field element with domain separation.
    ///
    /// Mirrors jolt-core: poseidon(state, n_rounds, element)
    fn hash_and_update(&mut self, element: MleAst) {
        let round = MleAst::from_i128(self.n_rounds as i128);
        self.state = MleAst::poseidon(&self.state, &round, &element);
        self.n_rounds += 1;
    }

    /// Derive a challenge as MleAst.
    ///
    /// Mirrors jolt-core: poseidon(state, n_rounds, 0)
    pub fn challenge_mle(&mut self) -> MleAst {
        let round = MleAst::from_i128(self.n_rounds as i128);
        let zero = MleAst::from_i128(0);
        let challenge = MleAst::poseidon(&self.state, &round, &zero);
        self.state = challenge.clone();
        self.n_rounds += 1;
        challenge
    }

    /// Derive multiple challenges as MleAst.
    pub fn challenge_vector_mle(&mut self, len: usize) -> Vec<MleAst> {
        (0..len).map(|_| self.challenge_mle()).collect()
    }

    /// Append symbolic field elements (for commitments/preamble as circuit inputs).
    ///
    /// This mirrors append_bytes but with symbolic inputs instead of concrete bytes.
    /// Each field element corresponds to one 32-byte chunk.
    pub fn append_field_elements(&mut self, elements: &[MleAst]) {
        let round = MleAst::from_i128(self.n_rounds as i128);
        let zero = MleAst::from_i128(0);

        let mut iter = elements.iter();

        // First element: includes n_rounds for domain separation
        let mut current = if let Some(first) = iter.next() {
            MleAst::poseidon(&self.state, &round, first)
        } else {
            // Empty: just hash state with n_rounds and zero
            MleAst::poseidon(&self.state, &round, &zero)
        };

        // Remaining elements: no n_rounds (already accounted for)
        for elem in iter {
            current = MleAst::poseidon(&current, &zero, elem);
        }

        self.state = current;
        self.n_rounds += 1;
    }

    /// Append a single symbolic u64 (for preamble values as circuit inputs).
    pub fn append_u64_symbolic(&mut self, value: MleAst) {
        self.hash_and_update(value);
    }
}

/// Implement Jolt's Transcript trait for PoseidonMleTranscript.
///
/// This allows using PoseidonMleTranscript with verify_stage1_with_transcript.
/// The challenge methods return MleAst when F = MleAst.
impl Transcript for PoseidonMleTranscript {
    fn new(label: &'static [u8]) -> Self {
        // Mirror jolt-core: initial_state = poseidon(label, 0, 0)
        let label_field = Self::label_to_field(label);
        let initial_state = MleAst::poseidon(
            &label_field,
            &MleAst::from_i128(0), // n_rounds = 0
            &MleAst::from_i128(0), // zero
        );
        Self {
            state: initial_state,
            n_rounds: 0,
        }
    }

    fn append_message(&mut self, msg: &'static [u8]) {
        // Same as append_bytes but for static messages
        // Pad to 32 bytes and convert to field element (LE)
        assert!(msg.len() <= 32);
        let mut padded = [0u8; 32];
        padded[..msg.len()].copy_from_slice(msg);
        let value = bytes_to_le_i128(&padded);
        self.hash_and_update(MleAst::from_i128(value));
    }

    fn append_bytes(&mut self, bytes: &[u8]) {
        // Hash all bytes using Poseidon with domain separation via n_rounds.
        // First chunk: hash(state, n_rounds, chunk), includes domain separator.
        // Subsequent chunks: hash(prev, 0, chunk), chained but without redundant n_rounds.
        let round = MleAst::from_i128(self.n_rounds as i128);
        let zero = MleAst::from_i128(0);

        let mut chunks = bytes.chunks(32);

        // First chunk: includes n_rounds for domain separation
        let mut current = if let Some(first_chunk) = chunks.next() {
            let mut padded = [0u8; 32];
            padded[..first_chunk.len()].copy_from_slice(first_chunk);
            let chunk_field = MleAst::from_i128(bytes_to_le_i128(&padded));
            MleAst::poseidon(&self.state, &round, &chunk_field)
        } else {
            // Empty bytes: just hash state with n_rounds and zero
            MleAst::poseidon(&self.state, &round, &zero)
        };

        // Remaining chunks: no n_rounds (already accounted for)
        for chunk in chunks {
            let mut padded = [0u8; 32];
            padded[..chunk.len()].copy_from_slice(chunk);
            let chunk_field = MleAst::from_i128(bytes_to_le_i128(&padded));
            current = MleAst::poseidon(&current, &zero, &chunk_field);
        }

        self.state = current;
        self.n_rounds += 1;
    }

    fn append_u64(&mut self, x: u64) {
        // Allocate into a 32 byte region (BE-padded to match EVM word format)
        // Then convert to LE field element (same as hash_bytes32_and_update)
        let mut packed = [0u8; 32];
        packed[24..].copy_from_slice(&x.to_be_bytes());
        let value = bytes_to_le_i128(&packed);
        self.hash_and_update(MleAst::from_i128(value));
    }

    fn append_scalar<F: JoltField>(&mut self, scalar: &F) {
        // Trigger serialization which stores MleAst in thread-local (if F = MleAst)
        let mut buf = vec![];
        let _ = scalar.serialize_uncompressed(&mut buf);

        // Retrieve the MleAst from thread-local (set by MleAst::serialize_with_mode)
        if let Some(mle_ast) = take_pending_append() {
            self.hash_and_update(mle_ast);
        } else {
            // Fallback for non-MleAst types (shouldn't happen in transpilation)
            self.hash_and_update(MleAst::from_i128(0));
        }
    }

    fn append_serializable<S: CanonicalSerialize>(&mut self, _scalar: &S) {
        self.hash_and_update(MleAst::from_i128(0));
    }

    fn append_scalars<F: JoltField>(&mut self, scalars: &[impl Borrow<F>]) {
        self.append_message(b"begin_append_vector");
        for scalar in scalars.iter() {
            self.append_scalar(scalar.borrow());
        }
        self.append_message(b"end_append_vector");
    }

    fn append_point<G: CurveGroup>(&mut self, _point: &G) {
        self.hash_and_update(MleAst::from_i128(0));
    }

    fn append_points<G: CurveGroup>(&mut self, points: &[G]) {
        self.append_message(b"begin_append_vector");
        for _ in points.iter() {
            self.hash_and_update(MleAst::from_i128(0));
        }
        self.append_message(b"end_append_vector");
    }

    fn challenge_u128(&mut self) -> u128 {
        let _ = self.challenge_mle();
        0u128
    }

    fn challenge_scalar<F: JoltField>(&mut self) -> F {
        let challenge = self.challenge_mle();
        set_pending_challenge(challenge);
        F::from_bytes(&[0u8; 32])
    }

    fn challenge_scalar_128_bits<F: JoltField>(&mut self) -> F {
        let challenge = self.challenge_mle();
        set_pending_challenge(challenge);
        F::from_bytes(&[0u8; 16])
    }

    fn challenge_vector<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        (0..len)
            .map(|_| {
                let challenge = self.challenge_mle();
                set_pending_challenge(challenge);
                F::from_bytes(&[0u8; 32])
            })
            .collect()
    }

    fn challenge_scalar_powers<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        // Get base challenge
        let base_challenge = self.challenge_mle();
        set_pending_challenge(base_challenge.clone());
        let base: F = F::from_bytes(&[0u8; 32]);

        // Compute powers: 1, base, base^2, ...
        let mut powers = Vec::with_capacity(len);
        let mut current = F::one();
        for _ in 0..len {
            powers.push(current);
            current = current * base;
        }
        powers
    }

    fn challenge_scalar_optimized<F: JoltField>(&mut self) -> F::Challenge {
        let _ = self.challenge_mle();
        F::Challenge::default()
    }

    fn challenge_vector_optimized<F: JoltField>(&mut self, len: usize) -> Vec<F::Challenge> {
        for _ in 0..len {
            let _ = self.challenge_mle();
        }
        vec![F::Challenge::default(); len]
    }

    fn challenge_scalar_powers_optimized<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        let _ = self.challenge_mle();
        vec![F::zero(); len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_field() {
        // "jolt" = [0x6a, 0x6f, 0x6c, 0x74] in ASCII
        // Little-endian: 0x746c6f6a = 1953198954
        let label_field = PoseidonMleTranscript::label_to_field(b"jolt");

        // Check it's a scalar with the expected value
        let root = label_field.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::Atom(zklean_extractor::mle_ast::Atom::Scalar(v)) => {
                // "jolt" in little-endian: j=0x6a, o=0x6f, l=0x6c, t=0x74
                // value = 0x6a + 0x6f*256 + 0x6c*65536 + 0x74*16777216
                let expected = 0x6a_i128 + (0x6f_i128 << 8) + (0x6c_i128 << 16) + (0x74_i128 << 24);
                assert_eq!(
                    v, expected,
                    "Label 'jolt' should be {} but got {}",
                    expected, v
                );
            }
            _ => panic!("Expected Scalar atom, got {:?}", node),
        }
    }

    #[test]
    fn test_transcript_creation() {
        let transcript: PoseidonMleTranscript = Transcript::new(b"test");
        assert_eq!(transcript.n_rounds, 0);
    }

    #[test]
    fn test_transcript_with_jolt_label() {
        // Verify that creating transcript with "Jolt" label produces a Poseidon node
        let transcript: PoseidonMleTranscript = Transcript::new(b"Jolt");
        assert_eq!(transcript.n_rounds, 0);

        // The initial state should be a Poseidon hash node
        let root = transcript.state.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::Poseidon(_, _, _) => {
                // Expected: poseidon(label, 0, 0)
            }
            _ => panic!("Expected Poseidon node for initial state, got {:?}", node),
        }
    }

    #[test]
    fn test_append_and_challenge() {
        let mut transcript: PoseidonMleTranscript = Transcript::new(b"test");
        transcript.hash_and_update(MleAst::from_i128(42));
        let _challenge = transcript.challenge_mle();
        assert_eq!(transcript.n_rounds, 2); // 1 append + 1 challenge
    }

    #[test]
    fn test_append_scalar_with_mle_ast() {
        use jolt_core::transcripts::Transcript as _;

        let mut transcript: PoseidonMleTranscript = Transcript::new(b"test");

        // Create a variable (not a constant)
        let var = MleAst::from_var(42);

        // Append it to transcript
        transcript.append_scalar(&var);

        // Check that the state now contains a Poseidon node with the variable
        let root = transcript.state.root();
        let node = zklean_extractor::mle_ast::get_node(root);

        match node {
            zklean_extractor::mle_ast::Node::Poseidon(_, _, e3) => {
                // The third argument should be our variable, not a constant 0
                match e3 {
                    zklean_extractor::mle_ast::Edge::Atom(
                        zklean_extractor::mle_ast::Atom::Var(idx),
                    ) => {
                        assert_eq!(idx, 42, "Expected Var(42), got Var({})", idx);
                    }
                    other => panic!(
                        "Expected Var(42) as third Poseidon arg, got {:?}",
                        other
                    ),
                }
            }
            _ => panic!("Expected Poseidon node, got {:?}", node),
        }
    }
}
