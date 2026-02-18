//! Blake2b transcript for symbolic execution (MleAst).
//!
//! Mirrors `jolt-core::transcripts::blake2b::Blake2bTranscript` but records
//! hash operations as `TranscriptHash(Blake2b, ...)` AST nodes instead of
//! computing concrete Blake2b hashes.
//!
//! # Key difference from Poseidon
//!
//! Blake2b hashes ALL data in a single call: `blake2b(state || pad(n_rounds) || data...)`.
//! Poseidon chains: `poseidon(poseidon(state, n_rounds, d0), 0, d1)`.
//!
//! This matters for `raw_append_bytes` and `append_serializable` — Blake2b uses a single
//! `TranscriptHash(Blake2b, state, rounds, [d0, d1, ..., dn])` node with variable arity,
//! while Poseidon chains multiple fixed-arity nodes.

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use jolt_core::field::JoltField;
use jolt_core::transcripts::Transcript;
use zklean_extractor::mle_ast::{
    set_pending_challenge, take_pending_append, take_pending_commitment_chunks, MleAst,
};

type Blake2b256 = Blake2b<U32>;

/// Symbolic Blake2b transcript for AST-based transpilation.
#[derive(Clone)]
pub struct Blake2bAstTranscript {
    /// Current state (symbolic field element)
    state: MleAst,
    /// Round counter for domain separation
    pub n_rounds: u32,
}

impl Blake2bAstTranscript {
    /// Convert a label to a field element (right-padded to 32 bytes).
    /// Same encoding as Poseidon — label bytes are the same.
    fn label_to_field(label: &[u8]) -> MleAst {
        assert!(label.len() <= 32, "Label must be <= 32 bytes");
        let mut padded = [0u8; 32];
        padded[..label.len()].copy_from_slice(label);
        MleAst::from(bytes_to_scalar(&padded))
    }

    /// Hash data elements into state using Blake2b.
    ///
    /// Creates: `TranscriptHash(Blake2b, state, n_rounds, data_elements)`
    fn hash_and_update(&mut self, element: MleAst) {
        self.hash_and_update_multi(&[element]);
    }

    /// Hash multiple data elements in a single Blake2b call.
    ///
    /// This is the fundamental difference from Poseidon: all data goes into
    /// one hash call, not chained across multiple calls.
    fn hash_and_update_multi(&mut self, data: &[MleAst]) {
        let round = MleAst::from_u64(self.n_rounds as u64);
        self.state = MleAst::blake2b(&self.state, &round, data);
        self.n_rounds += 1;
    }

    /// Derive a challenge: `blake2b(state, n_rounds, [])` (empty data), then update state.
    pub fn challenge_ast(&mut self) -> MleAst {
        let round = MleAst::from_u64(self.n_rounds as u64);
        let challenge = MleAst::blake2b(&self.state, &round, &[]);
        self.state = challenge;
        self.n_rounds += 1;
        challenge
    }
}

impl Transcript for Blake2bAstTranscript {
    fn new(label: &'static [u8]) -> Self {
        // Concrete Blake2b hash — label is always a compile-time constant.
        // Mirrors jolt-core: Blake2b256::new().chain_update(label).chain_update(zeros).finalize()
        assert!(label.len() < 33);
        let hasher = if label.len() == 32 {
            Blake2b256::new().chain_update(label)
        } else {
            let zeros = vec![0u8; 32 - label.len()];
            Blake2b256::new()
                .chain_update(label)
                .chain_update(zeros)
        };
        let out: [u8; 32] = hasher.finalize().into();
        let limbs = bytes_to_scalar(&out);

        Self {
            state: MleAst::from(limbs),
            n_rounds: 0,
        }
    }

    fn raw_append_label(&mut self, label: &'static [u8]) {
        let field = Self::label_to_field(label);
        self.hash_and_update(field);
    }

    fn raw_append_bytes(&mut self, bytes: &[u8]) {
        // KEY DIFFERENCE from Poseidon: collect ALL chunks, pass to single hash call.
        // blake2b(a||b) ≠ blake2b(blake2b(a)||b), so we can't chain.
        let elements: Vec<MleAst> = bytes
            .chunks(32)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[..chunk.len()].copy_from_slice(chunk);
                MleAst::from(bytes_to_scalar(&padded))
            })
            .collect();
        self.hash_and_update_multi(&elements);
    }

    fn raw_append_u64(&mut self, x: u64) {
        // Same encoding as Poseidon: bswap64(x) * 2^192
        let transformed = MleAst::append_u64_transform(&MleAst::from_u64(x));
        self.hash_and_update(transformed);
    }

    fn raw_append_scalar<F: JoltField>(&mut self, scalar: &F) {
        // Trigger serialization which stores MleAst in thread-local (if F = MleAst)
        let mut buf = vec![];
        let _ = scalar.serialize_uncompressed(&mut buf);

        if let Some(mle_ast) = take_pending_append() {
            // Same byte-reverse as Poseidon: serialize(LE) -> reverse -> from_le_bytes_mod_order
            let byte_reversed = MleAst::byte_reverse(&mle_ast);
            self.hash_and_update(byte_reversed);
        } else {
            self.hash_and_update(MleAst::from_u64(0));
        }
    }

    fn raw_append_point<G: CurveGroup>(&mut self, _point: &G) {
        // Symbolic no-op (same as Poseidon)
        self.hash_and_update(MleAst::from_u64(0));
    }

    fn append_serializable<T: CanonicalSerialize>(&mut self, label: &'static [u8], data: &T) {
        let mut buf = vec![];
        let _ = data.serialize_uncompressed(&mut buf);

        // Check for commitment chunks (12 MleAst for commitment hashing)
        if let Some(chunks) = take_pending_commitment_chunks() {
            let commitment_byte_len = chunks.len() * 32;
            self.raw_append_label_with_len(label, commitment_byte_len as u64);
            // KEY DIFFERENCE: single hash call with all chunks (not chained like Poseidon)
            self.hash_and_update_multi(&chunks);
            return;
        }

        // Fallback: single MleAst
        if let Some(mle_ast) = take_pending_append() {
            self.raw_append_label_with_len(label, buf.len() as u64);
            let byte_reversed = MleAst::byte_reverse(&mle_ast);
            self.hash_and_update(byte_reversed);
        } else {
            self.raw_append_label_with_len(label, buf.len() as u64);
            buf.reverse();
            self.raw_append_bytes(&buf);
        }
    }

    // === Challenge generation (identical to Poseidon — these are hash-agnostic) ===

    fn challenge_u128(&mut self) -> u128 {
        let _ = self.challenge_ast();
        0u128
    }

    fn challenge_scalar<F: JoltField>(&mut self) -> F {
        self.challenge_scalar_128_bits()
    }

    fn challenge_scalar_128_bits<F: JoltField>(&mut self) -> F {
        let hash = self.challenge_ast();
        let challenge = MleAst::truncate_128(&hash);
        set_pending_challenge(challenge);
        F::from_bytes(&[0u8; 16])
    }

    fn challenge_vector<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        (0..len).map(|_| self.challenge_scalar::<F>()).collect()
    }

    fn challenge_scalar_powers<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        let base: F = self.challenge_scalar();
        let mut powers = Vec::with_capacity(len);
        let mut current = F::one();
        for _ in 0..len {
            powers.push(current);
            current *= base;
        }
        powers
    }

    fn challenge_scalar_optimized<F: JoltField>(&mut self) -> F::Challenge {
        let hash = self.challenge_ast();
        let challenge = MleAst::truncate_128_reverse(&hash);
        set_pending_challenge(challenge);
        let f_val: F = F::from_bytes(&[0u8; 16]);
        unsafe { std::mem::transmute_copy::<F, F::Challenge>(&f_val) }
    }

    fn challenge_vector_optimized<F: JoltField>(&mut self, len: usize) -> Vec<F::Challenge> {
        (0..len)
            .map(|_| self.challenge_scalar_optimized::<F>())
            .collect()
    }

    fn challenge_scalar_powers_optimized<F: JoltField>(&mut self, len: usize) -> Vec<F> {
        let q: F::Challenge = self.challenge_scalar_optimized::<F>();
        let mut q_powers = vec![F::one(); len];
        for i in 1..len {
            q_powers[i] = q * q_powers[i - 1];
        }
        q_powers
    }

    fn debug_state(&self, _label: &str) {
        // No-op for symbolic execution
    }
}

impl Default for Blake2bAstTranscript {
    fn default() -> Self {
        Self {
            state: MleAst::from_u64(0),
            n_rounds: 0,
        }
    }
}

/// Convert 32 little-endian bytes to `[u64; 4]` limbs (no mod reduction).
fn bytes_to_scalar(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use jolt_core::transcripts::Transcript;

    #[test]
    fn test_transcript_creation() {
        let transcript: Blake2bAstTranscript = Transcript::new(b"test");
        assert_eq!(transcript.n_rounds, 0);
        // State should be a concrete scalar (from real blake2b), not a TranscriptHash node
        let root = transcript.state.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::Atom(zklean_extractor::mle_ast::Atom::Scalar(_)) => {
                // Expected: concrete blake2b result stored as scalar
            }
            _ => panic!("Expected concrete Scalar for Blake2b init, got {node:?}"),
        }
    }

    #[test]
    fn test_append_and_challenge() {
        let mut transcript: Blake2bAstTranscript = Transcript::new(b"test");
        transcript.hash_and_update(MleAst::from_u64(42));
        let _challenge = transcript.challenge_ast();
        assert_eq!(transcript.n_rounds, 2); // 1 append + 1 challenge
    }

    #[test]
    fn test_blake2b_uses_correct_backend() {
        let mut transcript: Blake2bAstTranscript = Transcript::new(b"test");
        transcript.hash_and_update(MleAst::from_u64(1));

        let root = transcript.state.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::TranscriptHash(
                zklean_extractor::mle_ast::TranscriptHashData::Blake2b(ref data), _, _
            ) => {
                assert_eq!(data.len(), 1, "hash_and_update should produce 1 data element");
            }
            _ => panic!("Expected TranscriptHash(Blake2b, ...) node, got {node:?}"),
        }
    }

    #[test]
    fn test_challenge_produces_empty_data() {
        let mut transcript: Blake2bAstTranscript = Transcript::new(b"test");
        let challenge = transcript.challenge_ast();

        let root = challenge.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::TranscriptHash(
                zklean_extractor::mle_ast::TranscriptHashData::Blake2b(ref data), _, _
            ) => {
                assert!(data.is_empty(), "challenge should produce empty data vec");
            }
            _ => panic!("Expected TranscriptHash(Blake2b, ...) node, got {node:?}"),
        }
    }

    #[test]
    fn test_concrete_init_matches_jolt_core() {
        // Verify our concrete init hash matches what jolt-core would produce
        let transcript: Blake2bAstTranscript = Transcript::new(b"Jolt");

        // Compute expected: blake2b("Jolt" || 28 zero bytes)
        let mut label_padded = vec![0u8; 32];
        label_padded[..4].copy_from_slice(b"Jolt");
        let expected: [u8; 32] = Blake2b256::new()
            .chain_update(&label_padded)
            .finalize()
            .into();
        let expected_limbs = bytes_to_scalar(&expected);

        let root = transcript.state.root();
        let node = zklean_extractor::mle_ast::get_node(root);
        match node {
            zklean_extractor::mle_ast::Node::Atom(zklean_extractor::mle_ast::Atom::Scalar(s)) => {
                assert_eq!(
                    s, expected_limbs,
                    "Blake2b init state doesn't match expected"
                );
            }
            _ => panic!("Expected concrete Scalar, got {node:?}"),
        }
    }
}
