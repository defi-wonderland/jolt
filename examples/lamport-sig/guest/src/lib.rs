#![cfg_attr(feature = "guest", no_std)]

// Toy hash function — not cryptographically secure, chosen for simplicity and no_std compatibility.
// Each key/signature element is a plain u64; no field arithmetic needed.
fn toy_hash(x: u64) -> u64 {
    let mut h = x ^ 0xcbf29ce484222325; // FNV offset basis
    h = h.wrapping_mul(0x100000001b3); // FNV prime
    h ^= h >> 33;
    h.wrapping_mul(0xff51afd7ed558ccd) // finalizer
}

// Lamport-OTS verification (n=32 variant).
//
// Public inputs : pk (64 u64s), message, result
// Private witness: sig (32 u64s) — hidden at the Groth16 level
//
// The proof says: "I know 32 values that each hash to the correct public-key
// entry for the corresponding bit of H(message)."
// The unused 32 preimage values (the other half of the private key) stay hidden.
//
// n=32 is chosen so the function signature fits within serde's fixed-array support
// (arrays up to [T; 32] only).  Security is intentionally negligible — this is a
// pedagogical demo, not a production signature scheme.
// Lamport is also a one-time signature (OTS): each key pair may only sign one message safely.
#[jolt::provable(heap_size = 4096, max_trace_length = 16384)]
fn lamport_verify(pk: [[u64; 2]; 16], message: u64, sig: [u64; 16]) -> bool {
    let msg_hash = toy_hash(message);
    let mut i = 0;
    while i < 16 {
        let bit = ((msg_hash >> i) & 1) as usize;
        if toy_hash(sig[i]) != pk[i][bit] {
            return false;
        }
        i += 1;
    }
    true
}
