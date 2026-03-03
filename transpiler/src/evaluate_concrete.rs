//! Evaluate an MleAst expression to a concrete BN254 field element.
//!
//! Used to convert symbolic challenge-derived values (captured during symbolic verification)
//! back to concrete Fr for witness fixup. Handles: Atom, Add, Mul, Sub, Inv, Neg,
//! and TranscriptHash(Poseidon). Byte operations (ByteReverse, Truncate128, etc.) are
//! NOT supported — they only appear with Blake2b/Keccak transcripts.

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{BigInt, Field, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

use zklean_extractor::mle_ast::{get_node, Atom, Edge, MleAst, Node, NodeId, TranscriptHashData};

/// Evaluate an MleAst expression to a concrete Fr value.
///
/// `var_values` maps variable indices to concrete Fr values (from VarAllocator.concrete_values()).
/// `cache` avoids re-evaluating shared sub-expressions in the DAG.
pub fn evaluate_concrete(
    ast: &MleAst,
    var_values: &[Fr],
    cache: &mut HashMap<NodeId, Fr>,
) -> Fr {
    eval_node(ast.root(), var_values, cache)
}

fn eval_node(
    node_id: NodeId,
    var_values: &[Fr],
    cache: &mut HashMap<NodeId, Fr>,
) -> Fr {
    if let Some(&cached) = cache.get(&node_id) {
        return cached;
    }

    let node = get_node(node_id);
    let result = match node {
        Node::Atom(atom) => eval_atom(&atom, var_values),
        Node::Add(a, b) => eval_edge(&a, var_values, cache) + eval_edge(&b, var_values, cache),
        Node::Mul(a, b) => eval_edge(&a, var_values, cache) * eval_edge(&b, var_values, cache),
        Node::Sub(a, b) => eval_edge(&a, var_values, cache) - eval_edge(&b, var_values, cache),
        Node::Neg(a) => -eval_edge(&a, var_values, cache),
        Node::Inv(a) => eval_edge(&a, var_values, cache)
            .inverse()
            .expect("evaluate_concrete: division by zero"),
        Node::Div(a, b) => {
            let denom = eval_edge(&b, var_values, cache);
            eval_edge(&a, var_values, cache) * denom.inverse().expect("div by zero")
        }
        Node::TranscriptHash(ref data, state_edge, n_rounds_edge) => {
            let state = eval_edge(&state_edge, var_values, cache);
            let n_rounds = eval_edge(&n_rounds_edge, var_values, cache);
            match data {
                TranscriptHashData::Poseidon(data_edge) => {
                    let input = eval_edge(data_edge, var_values, cache);
                    poseidon_hash(state, n_rounds, input)
                }
                TranscriptHashData::Blake2b(_) => {
                    panic!("evaluate_concrete: Blake2b not supported (only Poseidon)")
                }
            }
        }
        Node::ByteReverse(_)
        | Node::Truncate128Reverse(_)
        | Node::Truncate128(_)
        | Node::AppendU64Transform(_) => {
            panic!(
                "evaluate_concrete: byte operations not supported (only used with Blake2b/Keccak)"
            )
        }
    };

    cache.insert(node_id, result);
    result
}

fn eval_edge(edge: &Edge, var_values: &[Fr], cache: &mut HashMap<NodeId, Fr>) -> Fr {
    match edge {
        Edge::Atom(atom) => eval_atom(atom, var_values),
        Edge::NodeRef(id) => eval_node(*id, var_values, cache),
    }
}

fn eval_atom(atom: &Atom, var_values: &[Fr]) -> Fr {
    match atom {
        Atom::Scalar(limbs) => scalar_to_fr(limbs),
        Atom::Var(index) => var_values[*index as usize],
        Atom::NamedVar(index) => {
            panic!(
                "evaluate_concrete: NamedVar({index}) encountered — CSE bindings not supported. \
                 This function should only be called on raw AST before CSE."
            )
        }
    }
}

/// Convert MleAst Scalar ([u64; 4] raw value limbs) to ark_bn254::Fr.
///
/// MleAst stores field elements as raw value limbs (not Montgomery form).
/// Most values are in [0, p), but some may exceed p (e.g., from from_le_bytes_mod_order
/// which stores raw byte values). We reduce modulo p as needed.
fn scalar_to_fr(limbs: &[u64; 4]) -> Fr {
    let bigint = BigInt::new(*limbs);
    // Try direct conversion first (fast path for values < p)
    if let Some(fr) = Fr::from_bigint(bigint) {
        return fr;
    }
    // Value >= p. Convert via byte representation and reduce mod p.
    // This handles values from from_le_bytes_mod_order and similar.
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&limbs[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&limbs[1].to_le_bytes());
    bytes[16..24].copy_from_slice(&limbs[2].to_le_bytes());
    bytes[24..32].copy_from_slice(&limbs[3].to_le_bytes());
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Compute Poseidon hash: hash(state, n_rounds, input) using light-poseidon.
///
/// Matches the concrete Poseidon transcript implementation in jolt-core.
fn poseidon_hash(state: Fr, n_rounds: Fr, input: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(3).expect("Failed to initialize Poseidon");
    poseidon
        .hash(&[state, n_rounds, input])
        .expect("Poseidon hash failed")
}
