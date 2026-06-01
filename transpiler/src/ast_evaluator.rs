//! Concrete evaluation of AST nodes using real field arithmetic.
//!
//! Walks the `AstBundle` node arena and evaluates each node to a concrete `Fr` value.
//! Used for cross-validation: compare Rust AST evaluation against gnark circuit execution.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::collections::HashMap;
use zklean_extractor::ast_bundle::{Assertion, Constraint};
use zklean_extractor::mle_ast::{Atom, Edge, Node, NodeId, Scalar, TranscriptHashData};

/// Evaluate an Atom to Fr.
fn eval_atom(atom: &Atom, witness: &HashMap<u16, Fr>) -> Fr {
    match atom {
        Atom::Scalar(limbs) => scalar_to_fr(limbs),
        Atom::Var(idx) => *witness
            .get(idx)
            .unwrap_or_else(|| panic!("missing witness for Var({idx})")),
        Atom::NamedVar(_) => panic!("NamedVar should not appear in serialized bundle"),
    }
}

/// Convert a [u64; 4] scalar (raw, NOT Montgomery) to Fr.
fn scalar_to_fr(limbs: &Scalar) -> Fr {
    // Scalar is value-form (not Montgomery). Use from_le_bytes_mod_order.
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Resolve an `Edge` whose children have already been evaluated. `Edge::Atom`
/// is evaluated inline; `Edge::NodeRef(id)` is looked up in the cache. A
/// missing cache entry indicates a bug in the iterative walk, not malformed
/// input, hence the panic-on-missing.
fn eval_edge_cached(edge: &Edge, cache: &HashMap<NodeId, Fr>, witness: &HashMap<u16, Fr>) -> Fr {
    match edge {
        Edge::Atom(atom) => eval_atom(atom, witness),
        Edge::NodeRef(id) => *cache
            .get(id)
            .unwrap_or_else(|| panic!("iterative walk missed NodeRef({id}) in cache")),
    }
}

/// Combine a node into an `Fr`, assuming every `Edge::NodeRef` child is
/// already in `cache`. Mirrors the original recursive `eval_node` match but
/// resolves children via `eval_edge_cached` instead of recursion.
fn combine_node(node_id: NodeId, nodes: &[Node], cache: &HashMap<NodeId, Fr>, witness: &HashMap<u16, Fr>) -> Fr {
    match &nodes[node_id] {
        Node::Atom(atom) => eval_atom(atom, witness),

        Node::Add(a, b) => eval_edge_cached(a, cache, witness) + eval_edge_cached(b, cache, witness),
        Node::Sub(a, b) => eval_edge_cached(a, cache, witness) - eval_edge_cached(b, cache, witness),
        Node::Mul(a, b) => eval_edge_cached(a, cache, witness) * eval_edge_cached(b, cache, witness),
        Node::Div(a, b) => {
            let denom = eval_edge_cached(b, cache, witness);
            eval_edge_cached(a, cache, witness) * denom.inverse().expect("div by zero")
        }
        Node::Neg(a) => -eval_edge_cached(a, cache, witness),
        Node::Inv(a) => eval_edge_cached(a, cache, witness).inverse().expect("inv of zero"),

        Node::TranscriptHash(hash_data, state_edge, rounds_edge) => {
            let state = eval_edge_cached(state_edge, cache, witness);
            let rounds = eval_edge_cached(rounds_edge, cache, witness);

            match hash_data {
                TranscriptHashData::Poseidon(data_edge) => {
                    let data = eval_edge_cached(data_edge, cache, witness);
                    let mut hasher =
                        Poseidon::<Fr>::new_circom(3).expect("failed to create Poseidon hasher");
                    hasher
                        .hash(&[state, rounds, data])
                        .expect("Poseidon hash failed")
                }
                _ => panic!("only Poseidon transcript is supported for evaluation"),
            }
        }

        Node::ByteReverse(e) => {
            let val = eval_edge_cached(e, cache, witness);
            let bigint = val.into_bigint();
            let mut bytes = [0u8; 32];
            for (i, limb) in bigint.0.iter().enumerate() {
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
            }
            bytes.reverse();
            Fr::from_le_bytes_mod_order(&bytes)
        }

        Node::Truncate128Reverse(e) => {
            let val = eval_edge_cached(e, cache, witness);
            let bigint = val.into_bigint();
            let mut le_bytes = [0u8; 32];
            for (i, limb) in bigint.0.iter().enumerate() {
                le_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
            }
            let mut truncated = [0u8; 16];
            truncated.copy_from_slice(&le_bytes[..16]);
            truncated.reverse();
            let base = Fr::from_le_bytes_mod_order(&truncated);
            let shift = Fr::from(2u64).pow([128]);
            base * shift
        }

        Node::Truncate128(e) => {
            let val = eval_edge_cached(e, cache, witness);
            let bigint = val.into_bigint();
            let mut le_bytes = [0u8; 32];
            for (i, limb) in bigint.0.iter().enumerate() {
                le_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
            }
            let mut truncated = [0u8; 16];
            truncated.copy_from_slice(&le_bytes[..16]);
            truncated.reverse();
            Fr::from_le_bytes_mod_order(&truncated)
        }

        Node::AppendU64Transform(e) => {
            let val = eval_edge_cached(e, cache, witness);
            let bigint = val.into_bigint();
            let x = bigint.0[0];
            let swapped = x.swap_bytes();
            Fr::from(swapped) * Fr::from(2u64).pow([192])
        }
    }
}

/// Evaluate a node, caching results. Iterative DFS post-order with a
/// double-visit stack: first visit pushes the node back as "ready to combine"
/// then pushes its children; second visit combines (all children are cached
/// by then). The recursive form overflowed the default 8 MB stack on bundles
/// with deep linear chains (e.g. size_class padded AST trees with >32k
/// levels). Moving the stack to heap removes the limit; memory per frame is
/// ~16 bytes vs ~256 bytes for a real stack frame.
fn eval_node(
    root_id: NodeId,
    nodes: &[Node],
    cache: &mut HashMap<NodeId, Fr>,
    witness: &HashMap<u16, Fr>,
) -> Fr {
    let mut stack: Vec<(NodeId, bool)> = vec![(root_id, false)];

    while let Some((id, processed)) = stack.pop() {
        if cache.contains_key(&id) {
            continue;
        }

        if processed {
            let result = combine_node(id, nodes, cache, witness);
            cache.insert(id, result);
            continue;
        }

        // Re-push self marked as ready, then push unvisited NodeRef children
        // so they get evaluated first (LIFO post-order).
        stack.push((id, true));
        for child_id in nodes[id].child_node_ids() {
            if !cache.contains_key(&child_id) {
                stack.push((child_id, false));
            }
        }
    }

    *cache
        .get(&root_id)
        .expect("eval_node: root must be in cache after iterative walk")
}

/// Public adapter for code paths that need to evaluate a single `Edge`
/// (e.g. `evaluate_assertions` when decomposing `Sub(lhs, rhs)`). Resolves
/// `Edge::NodeRef` via the iterative `eval_node` so deep chains do not
/// overflow.
fn eval_edge(
    edge: &Edge,
    nodes: &[Node],
    cache: &mut HashMap<NodeId, Fr>,
    witness: &HashMap<u16, Fr>,
) -> Fr {
    match edge {
        Edge::Atom(atom) => eval_atom(atom, witness),
        Edge::NodeRef(id) => eval_node(*id, nodes, cache, witness),
    }
}

/// LHS and RHS of one assertion.
pub struct AssertionValue {
    pub name: String,
    pub lhs: Fr,
    pub rhs: Fr,
}

/// Evaluate all constraints in the bundle, returning LHS and RHS for each.
///
/// Only supports `Assertion::EqualZero`. If the root is `Sub(lhs, rhs)` the
/// two sides are returned separately; otherwise LHS is the expression and
/// RHS is 0. Panics on `EqualPublicInput` or `EqualNode`, which crossval
/// does not emit today.
pub fn evaluate_assertions(
    nodes: &[Node],
    constraints: &[Constraint],
    witness: &HashMap<u16, Fr>,
) -> Vec<AssertionValue> {
    let mut cache: HashMap<NodeId, Fr> = HashMap::new();
    let mut results = Vec::new();

    for constraint in constraints {
        match &constraint.assertion {
            Assertion::EqualZero => {}
            Assertion::EqualPublicInput { name } => panic!(
                "evaluate_assertions: Assertion::EqualPublicInput (name={name}) not supported. \
                 Update ast_evaluator.rs if crossval needs to handle this variant."
            ),
            Assertion::EqualNode(other) => panic!(
                "evaluate_assertions: Assertion::EqualNode(other={other}) not supported. \
                 Update ast_evaluator.rs if crossval needs to handle this variant."
            ),
        }

        let root_node = &nodes[constraint.root];

        let (lhs, rhs) = match root_node {
            // Most assertions: Sub(lhs, rhs) == 0 means lhs == rhs
            Node::Sub(lhs_edge, rhs_edge) => {
                let l = eval_edge(lhs_edge, nodes, &mut cache, witness);
                let r = eval_edge(rhs_edge, nodes, &mut cache, witness);
                (l, r)
            }
            // sum_zero or other: the whole expression should be 0
            _ => {
                let val = eval_node(constraint.root, nodes, &mut cache, witness);
                (val, Fr::from(0u64))
            }
        };

        results.push(AssertionValue {
            name: constraint.name.clone(),
            lhs,
            rhs,
        });
    }

    results
}

/// Convert Fr to decimal string (matching gnark's output format).
pub fn fr_to_decimal(f: &Fr) -> String {
    f.into_bigint().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_to_fr_zero() {
        let zero = scalar_to_fr(&[0, 0, 0, 0]);
        assert_eq!(zero, Fr::from(0u64));
    }

    #[test]
    fn test_scalar_to_fr_one() {
        let one = scalar_to_fr(&[1, 0, 0, 0]);
        assert_eq!(one, Fr::from(1u64));
    }

    #[test]
    fn test_scalar_to_fr_42() {
        let val = scalar_to_fr(&[42, 0, 0, 0]);
        assert_eq!(val, Fr::from(42u64));
    }

    // Pins the output of `light_poseidon::new_circom(3)` for two inputs, so a
    // version bump that silently changes the parameters trips this test. The
    // same decimals live in transpiler/go/poseidon/poseidon_test.go, which is
    // what actually cross-checks Go against Rust.
    #[test]
    fn test_light_poseidon_output_pinned() {
        use std::str::FromStr;

        let cases: [([Fr; 3], &str); 2] = [
            (
                [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)],
                "5317387130258456662214331362918410991734007599705406860481038345552731150762",
            ),
            (
                [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
                "6542985608222806190361240322586112750744169038454362455181422643027100751666",
            ),
        ];

        for (inputs, expected_dec) in cases {
            let mut hasher = Poseidon::<Fr>::new_circom(3).unwrap();
            let got = hasher.hash(&inputs).unwrap();
            let expected =
                Fr::from_str(expected_dec).expect("reference vector is valid decimal Fr");
            assert_eq!(got, expected);
        }
    }

    #[test]
    #[should_panic(expected = "Assertion::EqualPublicInput")]
    fn test_evaluate_assertions_panics_on_equal_public_input() {
        use zklean_extractor::ast_bundle::{Assertion, Constraint};

        let nodes = vec![Node::Atom(Atom::Scalar([0, 0, 0, 0]))];
        let constraints = vec![Constraint {
            name: "test".into(),
            root: 0,
            assertion: Assertion::EqualPublicInput { name: "x".into() },
        }];
        let witness = HashMap::new();
        let _ = evaluate_assertions(&nodes, &constraints, &witness);
    }

    #[test]
    #[should_panic(expected = "Assertion::EqualNode")]
    fn test_evaluate_assertions_panics_on_equal_node() {
        use zklean_extractor::ast_bundle::{Assertion, Constraint};

        let nodes = vec![Node::Atom(Atom::Scalar([0, 0, 0, 0]))];
        let constraints = vec![Constraint {
            name: "test".into(),
            root: 0,
            assertion: Assertion::EqualNode(0),
        }];
        let witness = HashMap::new();
        let _ = evaluate_assertions(&nodes, &constraints, &witness);
    }

    // Builds a linear AST of `Add(prev, 1)` chained DEPTH times. The recursive
    // form of `eval_node` overflowed the default 8 MB stack for chains beyond
    // ~30k. The iterative form must handle 100k without crashing.
    #[test]
    fn test_iterative_eval_survives_deep_chain() {
        use zklean_extractor::ast_bundle::{Assertion, Constraint};

        const DEPTH: usize = 100_000;
        let mut nodes: Vec<Node> = Vec::with_capacity(DEPTH + 1);
        nodes.push(Node::Atom(Atom::Scalar([1, 0, 0, 0])));
        for _ in 0..DEPTH {
            let prev = nodes.len() - 1;
            nodes.push(Node::Add(
                Edge::NodeRef(prev),
                Edge::Atom(Atom::Scalar([1, 0, 0, 0])),
            ));
        }
        let constraints = vec![Constraint {
            name: "deep_chain".into(),
            root: nodes.len() - 1,
            assertion: Assertion::EqualZero,
        }];
        let witness = HashMap::new();
        let result = evaluate_assertions(&nodes, &constraints, &witness);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lhs, Fr::from((DEPTH + 1) as u64));
        assert_eq!(result[0].rhs, Fr::from(0u64));
    }
}
