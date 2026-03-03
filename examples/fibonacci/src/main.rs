use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    // Parse CLI: fibonacci [--save] [N]
    // N defaults to 50 if not provided.
    let args: Vec<String> = std::env::args().collect();
    let save_to_disk = args.iter().any(|arg| arg == "--save");
    let n: u32 = args
        .iter()
        .filter(|a| *a != "--save" && !a.ends_with("fibonacci"))
        .find_map(|a| a.parse().ok())
        .unwrap_or(50);

    info!("Running fib({n}) save_to_disk={save_to_disk}");

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_fib(target_dir);

    let shared_preprocessing = guest::preprocess_shared_fib(&mut program);

    let prover_preprocessing = guest::preprocess_prover_fib(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing =
        guest::preprocess_verifier_fib(shared_preprocessing, verifier_setup);

    if save_to_disk {
        serialize_and_print_size(
            "Verifier Preprocessing",
            "/tmp/jolt_verifier_preprocessing.dat",
            &verifier_preprocessing,
        )
        .expect("Could not serialize preprocessing.");
    }

    let prove_fib = guest::build_prover_fib(program, prover_preprocessing);
    let verify_fib = guest::build_verifier_fib(verifier_preprocessing);

    let program_summary = guest::analyze_fib(n);
    program_summary
        .write_to_file("fib_10.txt".into())
        .expect("should write");

    let trace_file = "/tmp/fib_trace.bin";
    guest::trace_fib_to_file(trace_file, n);
    info!("Trace file written to: {trace_file}.");

    let now = Instant::now();
    let (output, proof, io_device) = prove_fib(n);
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());

    if save_to_disk {
        serialize_and_print_size("Proof", "/tmp/fib_proof.bin", &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", "/tmp/fib_io_device.bin", &io_device)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify_fib(n, output, io_device.panic, proof);
    info!("output: {output}");
    info!("valid: {is_valid}");
}
