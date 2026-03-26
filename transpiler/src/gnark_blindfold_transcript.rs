//! Poseidon transcript matching Jolt's `PoseidonTranscript` for BlindFold verification.
//!
//! This transcript is designed for the BlindFold verification circuit and matches
//! `jolt-core/src/transcripts/poseidon.rs` exactly:
//!
//! - `Hash(state, n_rounds, data)` for absorptions (32-byte chunks)
//! - `Hash(state, n_rounds, 0)` for challenge squeezing
//! - Labels: `from_le_bytes_mod_order(label_zero_padded_32)` — same as PoseidonTranscript
//! - Length-prefixed labels: pack label (24 bytes) + length (8 bytes BE) into 32-byte word
//! - Multi-chunk bytes: chain hash calls for >32 byte inputs
//! - Commitments: compressed BN254 G1 serialization → raw_append_bytes (trait default)
//!
//! The Go gnark circuit must implement the same protocol.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use light_poseidon::{Poseidon, PoseidonHasher};

use jolt_core::field::JoltField;
use jolt_core::transcripts::Transcript;

/// Poseidon hash width: 3 field elements (state, n_rounds, data).
const POSEIDON_WIDTH: usize = 3;

/// Bytes per field element chunk (BN254 Fr = 32 bytes).
const BYTES_PER_CHUNK: usize = 32;

/// Max label length when packed with a u64 length (24 + 8 = 32).
const MAX_LABEL_LEN_WITH_LENGTH: usize = 24;

/// Poseidon transcript matching Jolt's `PoseidonTranscript`.
///
/// Protocol:
/// - Init: `state = Hash(label, 0, 0)`, `n_rounds = 0`
/// - Absorb scalar: `state = Hash(state, n_rounds, scalar)`, `n_rounds++`
/// - Absorb bytes (≤32): `state = Hash(state, n_rounds, from_le(bytes))`, `n_rounds++`
/// - Absorb bytes (>32): chain hashes across 32-byte chunks, `n_rounds++` once
/// - Squeeze: `output = Hash(state, n_rounds, 0)`, `state = output`, `n_rounds++`
#[derive(Clone)]
pub struct GnarkBlindFoldTranscript {
    state: Fr,
    n_rounds: u32,
}

impl GnarkBlindFoldTranscript {
    fn hasher() -> Poseidon<Fr> {
        Poseidon::<Fr>::new_circom(POSEIDON_WIDTH).expect("Failed to initialize Poseidon for Fr")
    }

    /// Core absorption: `state = Hash(state, n_rounds, data); n_rounds++`
    fn absorb(&mut self, data: Fr) {
        let mut poseidon = Self::hasher();
        let round_f = Fr::from(self.n_rounds as u64);
        let output = poseidon
            .hash(&[self.state, round_f, data])
            .expect("Poseidon hash failed");
        self.state = output;
        self.n_rounds += 1;
    }

    /// Core squeeze: `output = Hash(state, n_rounds, 0); state = output; n_rounds++`
    fn squeeze(&mut self) -> Fr {
        let mut poseidon = Self::hasher();
        let round_f = Fr::from(self.n_rounds as u64);
        let zero = Fr::zero();
        let output = poseidon
            .hash(&[self.state, round_f, zero])
            .expect("Poseidon hash failed");
        self.state = output;
        self.n_rounds += 1;
        output
    }
}

impl Default for GnarkBlindFoldTranscript {
    fn default() -> Self {
        Self::new(b"default")
    }
}

impl Transcript for GnarkBlindFoldTranscript {
    fn new(label: &'static [u8]) -> Self {
        assert!(label.len() <= BYTES_PER_CHUNK);
        let mut poseidon = Self::hasher();
        let label_f = Fr::from_le_bytes_mod_order(label);
        let zero = Fr::zero();
        let state = poseidon
            .hash(&[label_f, zero, zero])
            .expect("Poseidon hash failed");
        Self {
            state,
            n_rounds: 0,
        }
    }

    // === Internal raw methods (matching PoseidonTranscript exactly) ===

    fn raw_append_label(&mut self, label: &'static [u8]) {
        assert!(label.len() <= BYTES_PER_CHUNK);
        // Zero-pad label to 32 bytes, interpret as LE Fr.
        // from_le_bytes_mod_order handles any length; trailing zeros = same value.
        let label_f = Fr::from_le_bytes_mod_order(label);
        self.absorb(label_f);
    }

    /// Pack label (right-padded, 24 bytes) and length (big-endian, 8 bytes) into 32-byte word.
    /// Matches PoseidonTranscript's trait default implementation.
    fn raw_append_label_with_len(&mut self, label: &'static [u8], len: u64) {
        assert!(
            label.len() <= MAX_LABEL_LEN_WITH_LENGTH,
            "Label too long for packed format: {} > {}",
            label.len(),
            MAX_LABEL_LEN_WITH_LENGTH
        );
        let mut packed = [0u8; 32];
        packed[..label.len()].copy_from_slice(label);
        packed[24..32].copy_from_slice(&len.to_be_bytes());
        let packed_f = Fr::from_le_bytes_mod_order(&packed);
        self.absorb(packed_f);
    }

    /// Absorb arbitrary-length bytes using chunking (matching PoseidonTranscript).
    /// - First chunk: `hash(state, n_rounds, chunk)` — includes domain separation
    /// - Subsequent chunks: `hash(prev, 0, chunk)` — chained without n_rounds
    /// - n_rounds increments once at the end.
    fn raw_append_bytes(&mut self, bytes: &[u8]) {
        let mut poseidon = Self::hasher();
        let state_f = self.state;
        let round_f = Fr::from(self.n_rounds as u64);
        let zero = Fr::zero();

        let mut chunks = bytes.chunks(BYTES_PER_CHUNK);

        // First hash: includes n_rounds for domain separation
        let first_chunk_f = chunks
            .next()
            .map(Fr::from_le_bytes_mod_order)
            .unwrap_or(zero);
        let mut current = poseidon
            .hash(&[state_f, round_f, first_chunk_f])
            .expect("Poseidon hash failed");

        // Remaining chunks: chain without n_rounds (use 0)
        for chunk in chunks {
            let chunk_f = Fr::from_le_bytes_mod_order(chunk);
            current = poseidon
                .hash(&[current, zero, chunk_f])
                .expect("Poseidon hash failed");
        }

        self.state = current;
        self.n_rounds += 1;
    }

    fn raw_append_u64(&mut self, x: u64) {
        // Pack as native LE: from_le_bytes_mod_order(packed) = x for small values
        let mut packed = [0u8; BYTES_PER_CHUNK];
        packed[..8].copy_from_slice(&x.to_le_bytes());
        let packed_f = Fr::from_le_bytes_mod_order(&packed);
        self.absorb(packed_f);
    }

    fn raw_append_scalar<JF: JoltField>(&mut self, scalar: &JF) {
        let mut buf = vec![];
        scalar.serialize_uncompressed(&mut buf).unwrap();
        // LE bytes of scalar → raw_append_bytes (matches PoseidonTranscript)
        self.raw_append_bytes(&buf);
    }

    // === Public API overrides ===

    // append_bytes: use trait default (raw_append_label_with_len + raw_append_bytes)
    // append_scalars: use trait default (raw_append_label_with_len + raw_append_scalar each)
    // append_commitment: use trait default (raw_append_label + serialize_compressed + raw_append_bytes)
    // append_commitments: use trait default (raw_append_label_with_len + serialize_compressed each)

    /// Override: skip buf.reverse() from the trait default (EVM compat not needed for Groth16).
    /// Matches PoseidonTranscript's override exactly.
    fn append_serializable<T: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        data: &T,
    ) {
        let mut buf = vec![];
        data.serialize_uncompressed(&mut buf).unwrap();
        self.raw_append_label_with_len(label, buf.len() as u64);
        // LE bytes directly, no byte reversal
        self.raw_append_bytes(&buf);
    }

    // === Challenge generation ===

    fn challenge_u128(&mut self) -> u128 {
        let output = self.squeeze();
        let mut buf = [0u8; 32];
        output
            .serialize_uncompressed(&mut buf[..])
            .expect("Fr serialization should not fail");
        u128::from_le_bytes(buf[..16].try_into().unwrap())
    }

    fn challenge_scalar<JF: JoltField>(&mut self) -> JF {
        self.challenge_scalar_128_bits()
    }

    fn challenge_scalar_128_bits<JF: JoltField>(&mut self) -> JF {
        let output = self.squeeze();
        let mut buf = [0u8; 32];
        output
            .serialize_uncompressed(&mut buf[..])
            .expect("Fr serialization should not fail");
        JF::from_bytes(&buf)
    }

    fn challenge_vector<JF: JoltField>(&mut self, len: usize) -> Vec<JF> {
        (0..len).map(|_| self.challenge_scalar()).collect()
    }

    fn challenge_scalar_powers<JF: JoltField>(&mut self, len: usize) -> Vec<JF> {
        let q: JF = self.challenge_scalar();
        let mut powers = vec![JF::one(); len];
        for i in 1..len {
            powers[i] = powers[i - 1] * q;
        }
        powers
    }

    fn challenge_scalar_optimized<JF: JoltField>(&mut self) -> JF::Challenge {
        let scalar: JF = self.challenge_scalar_128_bits();
        unsafe { std::mem::transmute_copy::<JF, JF::Challenge>(&scalar) }
    }

    fn challenge_vector_optimized<JF: JoltField>(&mut self, len: usize) -> Vec<JF::Challenge> {
        (0..len)
            .map(|_| self.challenge_scalar_optimized::<JF>())
            .collect()
    }

    fn challenge_scalar_powers_optimized<JF: JoltField>(&mut self, len: usize) -> Vec<JF> {
        let q: JF::Challenge = self.challenge_scalar_optimized::<JF>();
        let mut powers = vec![<JF as ark_std::One>::one(); len];
        for i in 1..len {
            powers[i] = q * powers[i - 1];
        }
        powers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use jolt_core::transcripts::PoseidonTranscript;

    #[test]
    fn test_init_state_matches_poseidon() {
        let gnark = GnarkBlindFoldTranscript::new(b"BlindFold");
        let poseidon = PoseidonTranscript::new(b"BlindFold");

        // Convert PoseidonTranscript state bytes to Fr for comparison
        let poseidon_state_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_state_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_label_matches_poseidon() {
        let mut gnark = GnarkBlindFoldTranscript::new(b"test");
        let mut poseidon = PoseidonTranscript::new(b"test");

        gnark.raw_append_label(b"my_label");
        poseidon.raw_append_label(b"my_label");

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_label_with_len_matches_poseidon() {
        let mut gnark = GnarkBlindFoldTranscript::new(b"test");
        let mut poseidon = PoseidonTranscript::new(b"test");

        gnark.raw_append_label_with_len(b"scalars", 5);
        poseidon.raw_append_label_with_len(b"scalars", 5);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_bytes_chunking_matches_poseidon() {
        // Test with >32 byte input (forces chunking)
        let mut gnark = GnarkBlindFoldTranscript::new(b"chunk");
        let mut poseidon = PoseidonTranscript::new(b"chunk");

        let data = vec![0xABu8; 65]; // 65 bytes = 3 chunks (32 + 32 + 1)
        gnark.raw_append_bytes(&data);
        poseidon.raw_append_bytes(&data);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_scalar_matches_poseidon() {
        let mut gnark = GnarkBlindFoldTranscript::new(b"test");
        let mut poseidon = PoseidonTranscript::new(b"test");

        let s = Fr::from(42u64);
        gnark.raw_append_scalar::<Fr>(&s);
        poseidon.raw_append_scalar::<Fr>(&s);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_scalars_matches_poseidon() {
        let mut gnark = GnarkBlindFoldTranscript::new(b"test");
        let mut poseidon = PoseidonTranscript::new(b"test");

        let scalars = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        gnark.append_scalars::<Fr>(b"coeff", &scalars);
        poseidon.append_scalars::<Fr>(b"coeff", &scalars);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_challenge_matches_poseidon() {
        let mut gnark = GnarkBlindFoldTranscript::new(b"challenge_test");
        let mut poseidon = PoseidonTranscript::new(b"challenge_test");

        gnark.raw_append_scalar::<Fr>(&Fr::from(123u64));
        poseidon.raw_append_scalar::<Fr>(&Fr::from(123u64));

        let gnark_challenge: Fr = gnark.challenge_scalar_128_bits();
        let poseidon_challenge: Fr = poseidon.challenge_scalar_128_bits();

        assert_eq!(gnark_challenge, poseidon_challenge);
    }

    #[test]
    fn test_append_commitment_matches_poseidon() {
        use jolt_core::curve::Bn254G1;
        use ark_bn254::G1Projective;
        use ark_std::UniformRand;

        let mut gnark = GnarkBlindFoldTranscript::new(b"com_test");
        let mut poseidon = PoseidonTranscript::new(b"com_test");

        let mut rng = ark_std::test_rng();
        let point = Bn254G1(G1Projective::rand(&mut rng));

        gnark.append_commitment(b"point", &point);
        poseidon.append_commitment(b"point", &point);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_append_commitments_matches_poseidon() {
        use jolt_core::curve::Bn254G1;
        use ark_bn254::G1Projective;
        use ark_std::UniformRand;

        let mut gnark = GnarkBlindFoldTranscript::new(b"coms_test");
        let mut poseidon = PoseidonTranscript::new(b"coms_test");

        let mut rng = ark_std::test_rng();
        let points: Vec<Bn254G1> = (0..3)
            .map(|_| Bn254G1(G1Projective::rand(&mut rng)))
            .collect();

        gnark.append_commitments(b"points", &points);
        poseidon.append_commitments(b"points", &points);

        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
        assert_eq!(gnark.n_rounds, poseidon.n_rounds);
    }

    #[test]
    fn test_full_blindfold_flow_matches_poseidon() {
        // Simulate the BlindFold verification transcript flow
        use jolt_core::curve::Bn254G1;
        use ark_bn254::G1Projective;
        use ark_std::UniformRand;

        let mut gnark = GnarkBlindFoldTranscript::new(b"BlindFold");
        let mut poseidon = PoseidonTranscript::new(b"BlindFold");

        let mut rng = ark_std::test_rng();

        // 1. append_label + append_instance_bytes pattern
        gnark.append_label(b"BlindFold_real_instance");
        poseidon.append_label(b"BlindFold_real_instance");

        // append_bytes (u serialization)
        let u = Fr::from(1u64);
        let mut u_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&u, &mut u_bytes).unwrap();
        gnark.append_bytes(b"blindfold_u", &u_bytes);
        poseidon.append_bytes(b"blindfold_u", &u_bytes);

        // append_commitments
        let coms: Vec<Bn254G1> = (0..3)
            .map(|_| Bn254G1(G1Projective::rand(&mut rng)))
            .collect();
        gnark.append_commitments(b"blindfold_round_coms", &coms);
        poseidon.append_commitments(b"blindfold_round_coms", &coms);

        // append_scalars
        let scalars = vec![Fr::from(10u64), Fr::from(20u64)];
        gnark.append_scalars::<Fr>(b"sumcheck_poly", &scalars);
        poseidon.append_scalars::<Fr>(b"sumcheck_poly", &scalars);

        // challenge
        let gnark_r: Fr = gnark.challenge_scalar_128_bits();
        let poseidon_r: Fr = poseidon.challenge_scalar_128_bits();
        assert_eq!(gnark_r, poseidon_r);

        // Final state check
        let poseidon_fr = Fr::from_le_bytes_mod_order(&poseidon.state);
        assert_eq!(gnark.state, poseidon_fr);
    }

    #[test]
    fn test_blindfold_packed_label_values() {
        use jolt_core::curve::Bn254G1;
        // Print packed label Fr values for Go cross-check
        let packed_u = {
            let mut packed = [0u8; 32];
            packed[..11].copy_from_slice(b"blindfold_u");
            packed[24..32].copy_from_slice(&32u64.to_be_bytes());
            Fr::from_le_bytes_mod_order(&packed)
        };
        let plain_u = Fr::from_le_bytes_mod_order(b"blindfold_u");
        let plain_real = Fr::from_le_bytes_mod_order(b"BlindFold_real_instance");

        println!("plain label 'BlindFold_real_instance' = {:?}", plain_real);
        println!("packed label 'blindfold_u' with len=32 = {:?}", packed_u);
        println!("plain label 'blindfold_u' = {:?}", plain_u);
        println!("packed != plain: {}", packed_u != plain_u);

        // Verify the init state
        let t = GnarkBlindFoldTranscript::new(b"BlindFold");
        println!("init state = {:?}", t.state);
        println!("init n_rounds = {}", t.n_rounds);

        // Also print compressed identity Fr
        let zero = Bn254G1(ark_bn254::G1Projective::default());
        let mut buf = vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed(&zero, &mut buf).unwrap();
        println!("identity compressed bytes ({} bytes): {:?}", buf.len(), buf);
        let identity_cfr = Fr::from_le_bytes_mod_order(&buf);
        println!("identity cfr = {:?}", identity_cfr);
    }
}
