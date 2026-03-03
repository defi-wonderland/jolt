//! Symbolization of IO device and bytecode for universal circuit generation.
//!
//! These functions convert concrete values (IO inputs/outputs, bytecode instructions)
//! into symbolic MleAst variables, enabling the generated circuit to be independent
//! of specific program inputs (same-program universality) and even the program itself
//! (cross-program universality via bytecode symbolization).

use common::jolt_device::JoltDevice;
use jolt_core::poly::commitment::dory::DoryCommitmentScheme;
use jolt_core::zkvm::ram::{set_pending_io_mle, PendingIoMleValues};
use jolt_core::zkvm::verifier::JoltVerifierPreprocessing;
use zklean_extractor::mle_ast::MleAst;

use crate::symbolic_proof::VarAllocator;

/// Symbolize IO device data for universal circuit generation.
///
/// Allocates symbolic variables for inputs, outputs, and panic, then pushes
/// override values to thread-locals consumed during `verify()`:
///
/// 1. **Preamble overrides** (`PENDING_BYTES_OVERRIDES`): Elements for Poseidon hashing
///    in `fiat_shamir_preamble`. Padded to max_input_size/max_output_size.
///
/// 2. **eval_io_mle overrides** (`PENDING_IO_MLE`): u64-word field elements for
///    `eval_io_mle_symbolic`. Padded to max_input_size/8 and max_output_size/8 words.
///
/// All IO is padded to max sizes from MemoryLayout so the circuit structure is
/// fixed regardless of actual IO size. `fiat_shamir_preamble` applies the same
/// padding on the prover side.
///
/// Returns `eval_input_words` for use in `PENDING_INITIAL_RAM`.
pub fn symbolize_io_device(
    io_device: &JoltDevice,
    var_alloc: &mut VarAllocator,
) -> Vec<MleAst> {
    use ark_ff::PrimeField;
    use crate::symbolic_traits::io_replay::push_bytes_override;

    let max_input = io_device.memory_layout.max_input_size as usize;
    let max_output = io_device.memory_layout.max_output_size as usize;

    // Pad inputs and outputs to max sizes (matches fiat_shamir_preamble padding).
    let mut padded_inputs = io_device.inputs.clone();
    padded_inputs.resize(max_input, 0);
    let mut padded_outputs = io_device.outputs.clone();
    padded_outputs.resize(max_output, 0);

    // --- 1. Preamble overrides (32-byte chunk scalars) ---
    // These match what raw_append_bytes produces: bytes → 32-byte padded → Fr scalar.
    let preamble_input_elements: Vec<MleAst> = padded_inputs
        .chunks(32)
        .enumerate()
        .map(|(i, chunk)| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            let concrete = ark_bn254::Fr::from_le_bytes_mod_order(&buf);
            var_alloc.alloc_with_value(&format!("io_preamble_input_{i}"), &concrete)
        })
        .collect();

    let preamble_output_elements: Vec<MleAst> = padded_outputs
        .chunks(32)
        .enumerate()
        .map(|(i, chunk)| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            let concrete = ark_bn254::Fr::from_le_bytes_mod_order(&buf);
            var_alloc.alloc_with_value(&format!("io_preamble_output_{i}"), &concrete)
        })
        .collect();

    // Panic → 8 bytes → 32-byte padded → Fr scalar → symbolic var
    let panic_u64 = io_device.panic as u64;
    let mut panic_padded = [0u8; 32];
    panic_padded[..8].copy_from_slice(&panic_u64.to_le_bytes());
    let panic_concrete = ark_bn254::Fr::from_le_bytes_mod_order(&panic_padded);
    let preamble_panic_element =
        var_alloc.alloc_with_value("io_preamble_panic", &panic_concrete);

    // Push in the exact order fiat_shamir_preamble calls append_bytes:
    // 1. inputs, 2. outputs, 3. panic
    push_bytes_override(preamble_input_elements);
    push_bytes_override(preamble_output_elements);
    push_bytes_override(vec![preamble_panic_element]);

    // --- 2. eval_io_mle overrides (u64-word field elements, padded to max) ---
    let num_input_words = max_input / 8;
    let num_output_words = max_output / 8;

    let eval_input_words: Vec<MleAst> = padded_inputs
        .chunks(8)
        .enumerate()
        .take(num_input_words)
        .map(|(i, chunk)| {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            let concrete = ark_bn254::Fr::from(val);
            var_alloc.alloc_with_value(&format!("io_eval_input_{i}"), &concrete)
        })
        .collect();

    let eval_output_words: Vec<MleAst> = padded_outputs
        .chunks(8)
        .enumerate()
        .take(num_output_words)
        .map(|(i, chunk)| {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            let concrete = ark_bn254::Fr::from(val);
            var_alloc.alloc_with_value(&format!("io_eval_output_{i}"), &concrete)
        })
        .collect();

    let eval_panic_val = {
        let concrete = ark_bn254::Fr::from(io_device.panic as u64);
        var_alloc.alloc_with_value("io_eval_panic", &concrete)
    };

    // Set pending IO MLE values (consumed by eval_io_mle)
    set_pending_io_mle(PendingIoMleValues {
        input_words: eval_input_words.clone(),
        output_words: eval_output_words,
        panic_val: eval_panic_val,
    });

    println!(
        "  Preamble: {} input chunks + {} output chunks + 1 panic",
        max_input / 32,
        max_output / 32,
    );
    println!(
        "  Eval: {} input words + {} output words + 1 panic",
        num_input_words, num_output_words,
    );

    eval_input_words
}

/// Tracks which variable indices need witness fixup after symbolic verification.
pub struct BytecodeFixupIndices {
    /// Variable indices for eq_r_register_4: [rd_eq4, rs1_eq4, rs2_eq4]
    pub eq_r4_var_indices: [u32; 3],
    /// Variable index for eq_r_register_5_rd
    pub eq_r5_rd_var_index: u32,
    /// Variable index for stage5_lookup_contribution
    pub lookup_contribution_var_index: u32,
}

/// Data returned by symbolize_bytecode for witness fixup after verify().
pub struct BytecodeSymbolizationData {
    /// Symbolic bytecode words for PENDING_INITIAL_RAM.
    pub bytecode_words: Vec<MleAst>,
    /// Concrete register indices per instruction (rd, rs1, rs2).
    pub register_indices: Vec<(Option<u8>, Option<u8>, Option<u8>)>,
    /// Concrete lookup table index per instruction (None if no lookup table).
    pub lookup_table_indices: Vec<Option<usize>>,
    /// Variable indices for challenge-dependent fields that need fixup.
    pub fixup_indices: Vec<BytecodeFixupIndices>,
}

/// Symbolize bytecode data for universal circuit generation (cross-program universality).
///
/// Allocates symbolic variables for:
/// 1. **bytecode_words** — RAM initialization values (for eval_initial_ram_mle)
/// 2. **instruction fields** — address, imm, flags, register eq lookups, lookup contribution
///    (for compute_val_polys). Challenge-dependent fields get placeholder (zero) witness values
///    that are fixed up after symbolic verification via `fixup_bytecode_witnesses()`.
///
/// Sets PENDING_BYTECODE_INSTRUCTIONS thread-local for compute_val_polys.
pub fn symbolize_bytecode(
    preprocessing: &JoltVerifierPreprocessing<ark_bn254::Fr, DoryCommitmentScheme>,
    var_alloc: &mut VarAllocator,
) -> BytecodeSymbolizationData {
    use jolt_core::field::JoltField;
    use jolt_core::zkvm::bytecode::read_raf_checking::{
        set_pending_bytecode_instructions, PendingBytecodeInstructions, SymbolicInstruction,
    };
    use jolt_core::zkvm::instruction::{
        Flags, InstructionLookup, InterleavedBitsMarker, NUM_CIRCUIT_FLAGS, NUM_INSTRUCTION_FLAGS,
    };
    use jolt_core::zkvm::lookup_table::LookupTables;
    use std::array;

    let bytecode = &preprocessing.shared.bytecode.bytecode;
    let bytecode_words = &preprocessing.shared.ram.bytecode_words;

    // 1. Bytecode words for eval_initial_ram_mle
    let sym_bytecode_words: Vec<MleAst> = bytecode_words
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let concrete = ark_bn254::Fr::from(w);
            var_alloc.alloc_with_value(&format!("bc_word_{i}"), &concrete)
        })
        .collect();

    // 2. Instruction fields for compute_val_polys
    let mut sym_instructions = Vec::with_capacity(bytecode.len());
    let mut register_indices = Vec::with_capacity(bytecode.len());
    let mut lookup_table_indices = Vec::with_capacity(bytecode.len());
    let mut fixup_indices = Vec::with_capacity(bytecode.len());

    for (k, instruction) in bytecode.iter().enumerate() {
        let instr = instruction.normalize();
        let cf = instruction.circuit_flags();
        let inf = instruction.instruction_flags();

        // Concrete fields (known at symbolization time)
        let address = var_alloc.alloc_with_value(
            &format!("bc_{k}_addr"),
            &ark_bn254::Fr::from(instr.address as u64),
        );
        let imm = var_alloc.alloc_with_value(
            &format!("bc_{k}_imm"),
            &ark_bn254::Fr::from_i128(instr.operands.imm),
        );
        let circuit_flags: [MleAst; NUM_CIRCUIT_FLAGS] = array::from_fn(|i| {
            var_alloc.alloc_with_value(
                &format!("bc_{k}_cf{i}"),
                &ark_bn254::Fr::from(cf[i] as u64),
            )
        });
        let instruction_flags: [MleAst; NUM_INSTRUCTION_FLAGS] = array::from_fn(|i| {
            var_alloc.alloc_with_value(
                &format!("bc_{k}_if{i}"),
                &ark_bn254::Fr::from(inf[i] as u64),
            )
        });
        let stage5_not_interleaved = var_alloc.alloc_with_value(
            &format!("bc_{k}_not_intl"),
            &ark_bn254::Fr::from(!cf.is_interleaved_operands() as u64),
        );

        // Challenge-dependent fields → placeholder zeros (fixed up after verify)
        let eq_r4_start = var_alloc.next_idx();
        let eq_r_register_4: [MleAst; 3] = {
            let names = ["rd", "rs1", "rs2"];
            array::from_fn(|i| {
                var_alloc.alloc_with_value(
                    &format!("bc_{k}_{}_eq4", names[i]),
                    &ark_bn254::Fr::from(0u64),
                )
            })
        };
        let eq5_idx = var_alloc.next_idx();
        let eq_r_register_5_rd = var_alloc.alloc_with_value(
            &format!("bc_{k}_rd_eq5"),
            &ark_bn254::Fr::from(0u64),
        );
        let lut_idx = var_alloc.next_idx();
        let stage5_lookup_contribution = var_alloc.alloc_with_value(
            &format!("bc_{k}_lut"),
            &ark_bn254::Fr::from(0u64),
        );

        fixup_indices.push(BytecodeFixupIndices {
            eq_r4_var_indices: [eq_r4_start, eq_r4_start + 1, eq_r4_start + 2],
            eq_r5_rd_var_index: eq5_idx,
            lookup_contribution_var_index: lut_idx,
        });

        sym_instructions.push(SymbolicInstruction {
            address,
            imm,
            circuit_flags,
            instruction_flags,
            eq_r_register_4,
            eq_r_register_5_rd,
            stage5_not_interleaved,
            stage5_lookup_contribution,
        });

        register_indices.push((instr.operands.rd, instr.operands.rs1, instr.operands.rs2));
        lookup_table_indices.push(
            instruction
                .lookup_table()
                .map(|t| LookupTables::<{ common::constants::XLEN }>::enum_index(&t)),
        );
    }

    // Set thread-local for compute_val_polys
    set_pending_bytecode_instructions(PendingBytecodeInstructions {
        instructions: sym_instructions,
        register_indices: register_indices.clone(),
        lookup_table_indices: lookup_table_indices.clone(),
    });

    println!(
        "  Bytecode words: {}, Instructions: {}",
        bytecode_words.len(),
        bytecode.len(),
    );
    println!(
        "  Variables per instruction: {} concrete + 5 challenge-dependent",
        2 + NUM_CIRCUIT_FLAGS + NUM_INSTRUCTION_FLAGS + 1, // addr + imm + cf + if + not_intl
    );

    BytecodeSymbolizationData {
        bytecode_words: sym_bytecode_words,
        register_indices,
        lookup_table_indices,
        fixup_indices,
    }
}

/// Fix up challenge-dependent witness values in bytecode symbolization.
///
/// After symbolic verification, CapturedBytecodeData contains the concrete eq_r_register
/// tables and stage5_gammas as MleAst expressions. We evaluate these to Fr and use them
/// to compute the correct witness values for each instruction's placeholder fields.
pub fn fixup_bytecode_witnesses(
    bytecode_data: &BytecodeSymbolizationData,
    var_alloc: &mut VarAllocator,
) {
    use jolt_core::zkvm::bytecode::read_raf_checking::{
        take_captured_bytecode_data, CapturedBytecodeData,
    };
    use std::collections::HashMap;
    use crate::evaluate_concrete::evaluate_concrete;

    let captured: CapturedBytecodeData<MleAst> = take_captured_bytecode_data()
        .expect("CapturedBytecodeData not set — verify() may not have reached stage 6");

    // Evaluate the symbolic eq_r_register tables and gammas to concrete Fr.
    let var_values = var_alloc.concrete_values();
    let mut cache = HashMap::new();

    let eq_r4_table: Vec<ark_bn254::Fr> = captured
        .eq_r_register_4
        .iter()
        .map(|ast| evaluate_concrete(ast, var_values, &mut cache))
        .collect();
    let eq_r5_table: Vec<ark_bn254::Fr> = captured
        .eq_r_register_5
        .iter()
        .map(|ast| evaluate_concrete(ast, var_values, &mut cache))
        .collect();
    let stage5_gammas: Vec<ark_bn254::Fr> = captured
        .stage5_gammas
        .iter()
        .map(|ast| evaluate_concrete(ast, var_values, &mut cache))
        .collect();

    println!("\n=== Fixing Up Bytecode Witnesses ===");
    println!(
        "  eq_r_register_4 table: {} entries",
        eq_r4_table.len()
    );
    println!(
        "  eq_r_register_5 table: {} entries",
        eq_r5_table.len()
    );
    println!(
        "  stage5_gammas: {} entries",
        stage5_gammas.len()
    );

    // Fix up each instruction's placeholder witness values.
    let mut fixed_count = 0;
    for (k, fixup) in bytecode_data.fixup_indices.iter().enumerate() {
        let (rd, rs1, rs2) = bytecode_data.register_indices[k];
        let table_idx = bytecode_data.lookup_table_indices[k];

        // eq_r_register_4: [rd_eq4, rs1_eq4, rs2_eq4]
        let rd_eq4 = rd.map_or(ark_bn254::Fr::from(0u64), |r| eq_r4_table[r as usize]);
        let rs1_eq4 = rs1.map_or(ark_bn254::Fr::from(0u64), |r| eq_r4_table[r as usize]);
        let rs2_eq4 = rs2.map_or(ark_bn254::Fr::from(0u64), |r| eq_r4_table[r as usize]);
        var_alloc.update_witness(fixup.eq_r4_var_indices[0], &rd_eq4);
        var_alloc.update_witness(fixup.eq_r4_var_indices[1], &rs1_eq4);
        var_alloc.update_witness(fixup.eq_r4_var_indices[2], &rs2_eq4);

        // eq_r_register_5_rd
        let rd_eq5 = rd.map_or(ark_bn254::Fr::from(0u64), |r| eq_r5_table[r as usize]);
        var_alloc.update_witness(fixup.eq_r5_rd_var_index, &rd_eq5);

        // stage5_lookup_contribution
        let lut_val = table_idx.map_or(ark_bn254::Fr::from(0u64), |idx| stage5_gammas[2 + idx]);
        var_alloc.update_witness(fixup.lookup_contribution_var_index, &lut_val);

        fixed_count += 5;
    }
    println!("  Fixed {} witness values", fixed_count);
}
