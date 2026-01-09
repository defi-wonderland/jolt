//! Print Poseidon test vectors for comparison with Go implementation
//!
//! Uses jolt-core's PoseidonTranscript which wraps light-poseidon

use ark_bn254::Fr;
use jolt_core::transcripts::{FrParams, PoseidonParams, PoseidonTranscript, Transcript};
use light_poseidon::PoseidonHasher;

fn main() {
    println!("=== Poseidon Test Vectors (light-poseidon circom t=4) ===\n");

    // Test hash using the same interface as the transcript
    println!("=== Test Hash Vectors ===");

    // Direct Poseidon hash: hash([1, 2, 3])
    let mut hasher = FrParams::poseidon();
    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let result = hasher.hash(&inputs).expect("hash failed");
    println!("hash([1, 2, 3]) = {:?}", result);

    // Direct Poseidon hash: hash([0, 0, 0])
    let mut hasher2 = FrParams::poseidon();
    let zero_inputs = [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)];
    let zero_result = hasher2.hash(&zero_inputs).expect("hash failed");
    println!("hash([0, 0, 0]) = {:?}", zero_result);

    // Transcript test: simulate what the circuit does
    println!("\n=== Transcript Test ===");
    let mut transcript: PoseidonTranscript<Fr, FrParams> = Transcript::new(b"Jolt");

    // Append a scalar
    transcript.append_scalar(&Fr::from(42u64));
    let challenge = transcript.challenge_scalar();
    println!("After append(42), challenge = {:?}", challenge);
}
