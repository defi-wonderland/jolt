use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let save_to_disk = args.iter().any(|arg| arg == "--save");

    // Parse input: last numeric CLI argument, or default to 50.
    // E.g., `fibonacci --save 80` → input=80, `fibonacci --save` → input=50.
    let input: u32 = args
        .iter()
        .rev()
        .find_map(|s| s.parse().ok())
        .unwrap_or(50);

    let force_class: Option<&str> = args
        .iter()
        .position(|a| a == "--class")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_fib(target_dir);

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
            heap_size: 32768,
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
        guest::preprocess_shared_fib(&mut program).unwrap()
    };

    let prover_preprocessing = guest::preprocess_prover_fib(shared_preprocessing.clone());
    let verifier_setup = prover_preprocessing.generators.to_verifier_setup();
    let verifier_preprocessing =
        guest::preprocess_verifier_fib(shared_preprocessing, verifier_setup, None);

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

    let program_summary = guest::analyze_fib(10);
    program_summary
        .write_to_file("fib_10.txt".into())
        .expect("should write");

    let trace_file = "/tmp/fib_trace.bin";
    guest::trace_fib_to_file(trace_file, input);
    info!("Trace file written to: {trace_file}.");

    let now = Instant::now();
    let (output, proof, io_device) = prove_fib(input);
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());

    if save_to_disk {
        serialize_and_print_size("Proof", "/tmp/fib_proof.bin", &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", "/tmp/fib_io_device.bin", &io_device)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify_fib(input, output, io_device.panic, proof);
    info!("output: {output}");
    info!("valid: {is_valid}");
}
