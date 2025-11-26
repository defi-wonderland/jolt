//! Gnark Transpiler CLI
//!
//! Transpiles Jolt's Stage 1 verifier into Gnark circuits.
//!
//! Usage:
//!   cargo run -- --output stage1_circuit.go
//!   cargo run -- --output go/stage1_circuit.go --circuit-name Stage1Circuit

use gnark_transpiler::{export_stage1_ast, generate_stage1_circuit};
use jolt_core::zkvm::stage1_only_verifier::{
    verify_stage1_for_transpilation, Stage1VerificationData,
};
use std::fs;
use std::path::PathBuf;
use zklean_extractor::mle_ast::MleAst;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments
    let mut output_path = PathBuf::from("stage1_circuit.go");
    let mut circuit_name = "Stage1Circuit";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_path = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a path argument");
                    std::process::exit(1);
                }
            }
            "--circuit-name" | "-n" => {
                if i + 1 < args.len() {
                    circuit_name = &args[i + 1];
                    i += 2;
                } else {
                    eprintln!("Error: --circuit-name requires a name argument");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
    }

    println!("Gnark Transpiler for Jolt Stage 1 Verifier");
    println!("==========================================");
    println!();

    // Create MleAst variables for circuit inputs
    // These will be the public inputs to the Gnark circuit
    println!("Creating circuit variables...");

    // trace_length=8 means log2(8)=3 sumcheck rounds
    // Variables are assigned sequentially:
    let trace_length = 8;
    let num_rounds = (trace_length as f64).log2() as usize; // 3 rounds

    let mut var_idx = 0u16;

    // tau: num_rounds variables
    let tau: Vec<MleAst> = (0..num_rounds)
        .map(|_| {
            let v = MleAst::from_var(var_idx);
            var_idx += 1;
            v
        })
        .collect();

    // sumcheck_challenges: num_rounds variables
    let sumcheck_challenges: Vec<MleAst> = (0..num_rounds)
        .map(|_| {
            let v = MleAst::from_var(var_idx);
            var_idx += 1;
            v
        })
        .collect();

    // r0: 1 variable
    let r0 = MleAst::from_var(var_idx);
    var_idx += 1;

    // uni_skip_poly_coeffs: num_rounds + 1 coefficients (degree num_rounds polynomial)
    let uni_skip_poly_coeffs: Vec<MleAst> = (0..=num_rounds)
        .map(|_| {
            let v = MleAst::from_var(var_idx);
            var_idx += 1;
            v
        })
        .collect();

    // sumcheck_round_polys: num_rounds polynomials, each with 2 coefficients
    let sumcheck_round_polys: Vec<Vec<MleAst>> = (0..num_rounds)
        .map(|_| {
            let poly: Vec<MleAst> = (0..2)
                .map(|_| {
                    let v = MleAst::from_var(var_idx);
                    var_idx += 1;
                    v
                })
                .collect();
            poly
        })
        .collect();

    println!("  trace_length: {}", trace_length);
    println!("  num_rounds: {}", num_rounds);
    println!("  total variables: {}", var_idx);

    let data = Stage1VerificationData {
        tau,
        r0,
        sumcheck_challenges,
        uni_skip_poly_coeffs,
        sumcheck_round_polys,
        trace_length,
    };

    // Run the verifier with MleAst - this builds the AST automatically
    println!("Running Stage 1 verifier with MleAst (building AST)...");
    let result = verify_stage1_for_transpilation(data);

    // Generate Gnark circuit code from the AST
    println!("Generating Gnark circuit code...");
    let go_code = generate_stage1_circuit(&result, circuit_name);

    // Write to file
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).expect("Failed to create output directory");
        }
    }

    fs::write(&output_path, &go_code).expect("Failed to write output file");

    // Also export AST to JSON
    let ast_path = output_path.with_extension("ast.json");
    println!("Exporting AST to JSON...");
    let ast_json = export_stage1_ast(&result, trace_length);
    let ast_json_str = ast_json.to_json().expect("Failed to serialize AST");
    fs::write(&ast_path, &ast_json_str).expect("Failed to write AST file");

    // Export Mermaid diagram
    let mermaid_path = output_path.with_extension("ast.md");
    println!("Generating Mermaid diagram...");
    let mermaid_str = ast_json.to_mermaid();
    fs::write(&mermaid_path, &mermaid_str).expect("Failed to write Mermaid file");

    println!();
    println!("✓ Generated Gnark circuit: {}", output_path.display());
    println!("✓ Exported AST: {}", ast_path.display());
    println!("✓ Exported diagram: {}", mermaid_path.display());
    println!("  Circuit name: {}", circuit_name);
    println!("  Nodes in AST: {}", ast_json.nodes.len());
    println!("  Constraints: {}", ast_json.constraints.len());
    println!("  Variables: {:?}", ast_json.variables);
}

fn print_help() {
    println!("Gnark Transpiler for Jolt Stage 1 Verifier");
    println!();
    println!("USAGE:");
    println!("    gnark-transpiler [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -o, --output <PATH>         Output file path (default: stage1_circuit.go)");
    println!("    -n, --circuit-name <NAME>   Circuit struct name (default: Stage1Circuit)");
    println!("    -h, --help                  Print help information");
    println!();
    println!("EXAMPLES:");
    println!("    gnark-transpiler --output go/stage1_circuit.go");
    println!("    gnark-transpiler -o circuit.go -n MyCircuit");
}
