use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let save_to_disk = args.iter().any(|arg| arg == "--save");
    let force_class: Option<&str> = args
        .iter()
        .position(|a| a == "--class")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_muldiv(target_dir);

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
        guest::preprocess_shared_muldiv(&mut program).unwrap()
    };

    let prover_preprocessing = guest::preprocess_prover_muldiv(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_muldiv(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
        None,
    );

    if save_to_disk {
        serialize_and_print_size(
            "Verifier Preprocessing",
            "/tmp/jolt_verifier_preprocessing.dat",
            &verifier_preprocessing,
        )
        .expect("Could not serialize preprocessing.");
    }

    let prove = guest::build_prover_muldiv(program, prover_preprocessing);
    let verify = guest::build_verifier_muldiv(verifier_preprocessing);

    let now = Instant::now();
    let (output, proof, program_io) = prove(12031293, 17, 92);
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());

    if save_to_disk {
        serialize_and_print_size("Proof", "/tmp/muldiv_proof.bin", &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", "/tmp/muldiv_io_device.bin", &program_io)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify(12031293, 17, 92, output, program_io.panic, proof);
    info!("output: {output}");
    info!("valid: {is_valid}");
}
