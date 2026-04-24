use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let save_to_disk = std::env::args().any(|arg| arg == "--save");

    // Prove/verify convergence for a single number:
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_collatz_convergence(target_dir);

    let shared_preprocessing = guest::preprocess_shared_collatz_convergence(&mut program).unwrap();
    let prover_preprocessing =
        guest::preprocess_prover_collatz_convergence(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing =
        guest::preprocess_verifier_collatz_convergence(shared_preprocessing, verifier_setup, None);

    if save_to_disk {
        serialize_and_print_size(
            "Verifier Preprocessing",
            "/tmp/jolt_verifier_preprocessing.dat",
            &verifier_preprocessing,
        )
        .expect("Could not serialize preprocessing.");
    }

    let prove_collatz_single =
        guest::build_prover_collatz_convergence(program, prover_preprocessing);
    let verify_collatz_single = guest::build_verifier_collatz_convergence(verifier_preprocessing);

    let now = Instant::now();
    let input = 19;
    let (output, proof, program_io) = prove_collatz_single(input);
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());

    if save_to_disk {
        serialize_and_print_size("Proof", "/tmp/collatz_proof.bin", &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", "/tmp/collatz_io_device.bin", &program_io)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify_collatz_single(input, output, program_io.panic, proof);

    info!("output: {output}");
    info!("valid: {is_valid}");

    // Skip the range variant when saving — the transpiler consumes a single
    // proof artifact, so only the single-convergence run above is relevant.
    if save_to_disk {
        return;
    }

    // Prove/verify convergence for a range of numbers:
    let mut program = guest::compile_collatz_convergence_range(target_dir);

    let shared_preprocessing =
        guest::preprocess_shared_collatz_convergence_range(&mut program).unwrap();
    let prover_preprocessing =
        guest::preprocess_prover_collatz_convergence_range(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing = guest::preprocess_verifier_collatz_convergence_range(
        shared_preprocessing,
        verifier_setup,
        None,
    );

    let prove_collatz_convergence =
        guest::build_prover_collatz_convergence_range(program, prover_preprocessing);
    let verify_collatz_convergence =
        guest::build_verifier_collatz_convergence_range(verifier_preprocessing);

    // https://www.reddit.com/r/compsci/comments/gk9x6g/collatz_conjecture_news_recently_i_managed_to/
    let start: u128 = 1 << 68;
    let now = Instant::now();
    let (output, proof, program_io) = prove_collatz_convergence(start, start + 100);
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());
    let is_valid = verify_collatz_convergence(start, start + 100, output, program_io.panic, proof);

    info!("output: {output}");
    info!("valid: {is_valid}");
}
