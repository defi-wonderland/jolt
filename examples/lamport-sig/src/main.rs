use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

// ── Toy hash (must match guest/src/lib.rs) ────────────────────────────────────

fn toy_hash(x: u64) -> u64 {
    let mut h = x ^ 0xcbf29ce484222325;
    h = h.wrapping_mul(0x100000001b3);
    h ^= h >> 33;
    h.wrapping_mul(0xff51afd7ed558ccd)
}

// ── Key generation ────────────────────────────────────────────────────────────

fn keygen(seed: u64) -> ([[u64; 2]; 16], [[u64; 2]; 16]) {
    let mut sk = [[0u64; 2]; 16];
    let mut pk = [[0u64; 2]; 16];
    for i in 0..16 {
        for b in 0..2 {
            // Derive each secret key element deterministically from the seed.
            sk[i][b] = toy_hash(seed ^ ((i as u64) << 8 | b as u64));
            pk[i][b] = toy_hash(sk[i][b]);
        }
    }
    (sk, pk)
}

// ── Signing ───────────────────────────────────────────────────────────────────

fn sign(sk: &[[u64; 2]; 16], message: u64) -> [u64; 16] {
    let msg_hash = toy_hash(message);
    let mut sig = [0u64; 16];
    for i in 0..16 {
        let bit = ((msg_hash >> i) & 1) as usize;
        sig[i] = sk[i][bit];
    }
    sig
}

// ── Test vectors ──────────────────────────────────────────────────────────────
//
// Each signer is derived from a fixed seed for reproducibility.
// Signer 1 and 2 use different seeds and messages so they produce
// independent key pairs — useful for future cross-signer verification.

const SEED_1: u64 = 0x1a2b3c4d_5e6f7a8b;
const MSG_1: u64 = 0xdeadbeef_cafef00d;

const SEED_2: u64 = 0xfeedface_deadc0de;
const MSG_2: u64 = 0x0badf00d_cafebabe;

// ── Main ──────────────────────────────────────────────────────────────────────

pub fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let save = args.iter().any(|a| a == "--save");
    let signer: u32 = args
        .iter()
        .position(|a| a == "--signer")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let force_class: Option<&str> = args
        .iter()
        .position(|a| a == "--class")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let (seed, message) = match signer {
        1 => (SEED_1, MSG_1),
        2 => (SEED_2, MSG_2),
        s => panic!("Unknown signer {s}. Use --signer 1 or --signer 2."),
    };

    info!("Using signer {signer}");

    let (sk, pk) = keygen(seed);
    let sig = sign(&sk, message);

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_lamport_verify(target_dir);

    let shared_preprocessing = if let Some(class_name) = force_class {
        use jolt_sdk::{JoltSharedPreprocessing, MemoryConfig, MemoryLayout};
        let class = jolt_sdk::size_class::find_class_by_name(class_name)
            .unwrap_or_else(|| panic!("Unknown size class: {class_name}"));

        let (bytecode, memory_init, program_size, entry_address) = program.decode();
        let memory_config = MemoryConfig {
            max_input_size: 4096,
            max_output_size: 4096,
            max_untrusted_advice_size: 4096,
            max_trusted_advice_size: 4096,
            stack_size: 4096,
            heap_size: 4096,
            program_size: Some(program_size),
        };
        let memory_layout = MemoryLayout::new(&memory_config);

        info!(
            "Forcing size class {} (log_T={}, bytecode_K={}, ram_K={})",
            class.name, class.max_log_t, class.max_bytecode_k, class.max_ram_k
        );
        JoltSharedPreprocessing::new_with_targets(
            bytecode,
            memory_layout,
            memory_init,
            65536,
            entry_address,
            Some(1 << class.max_log_t),
            Some(class.max_ram_k),
            Some(class.max_bytecode_k),
        )
        .unwrap()
    } else {
        guest::preprocess_shared_lamport_verify(&mut program).unwrap()
    };

    let prover_preprocessing =
        guest::preprocess_prover_lamport_verify(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_lamport_verify(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
        None,
    );

    if save {
        serialize_and_print_size(
            "Verifier Preprocessing",
            "/tmp/jolt_verifier_preprocessing.dat",
            &verifier_preprocessing,
        )
        .expect("Could not serialize preprocessing.");
    }

    let prove = guest::build_prover_lamport_verify(program, prover_preprocessing);
    let verify = guest::build_verifier_lamport_verify(verifier_preprocessing);

    let now = Instant::now();
    let (output, proof, program_io) = prove(pk, message, sig);
    info!("Prover runtime: {:.2} s", now.elapsed().as_secs_f64());

    let (proof_path, io_path) = match signer {
        1 => ("/tmp/lamport_proof_1.bin", "/tmp/lamport_io_device_1.bin"),
        2 => ("/tmp/lamport_proof_2.bin", "/tmp/lamport_io_device_2.bin"),
        _ => unreachable!(),
    };

    if save {
        serialize_and_print_size("Proof", proof_path, &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", io_path, &program_io)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify(pk, message, sig, output, program_io.panic, proof);
    info!("lamport_verify(signer={signer}, message={message:#x}): {output}");
    info!("proof valid: {is_valid}");
}
