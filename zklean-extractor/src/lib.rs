//! ZkLean Extractor Library
//!
//! Provides the MleAst symbolic field type for transpiling Jolt verifier
//! operations to external circuit representations.
//!
//! ## Module Structure
//!
//! - `mle_ast`: Core AST types (MleAst, Node, Atom, Edge) and JoltField implementation
//! - `scalar_ops`: Modular arithmetic for BN254 scalar field elements
//! - `ast_bundle`: Serializable IR types for transpilation (AstBundle, AstCommitment)

// Lean extraction modules
pub mod constants;
pub mod instruction;
pub mod lean_tests;
pub mod lookups;
pub mod modules;
pub mod r1cs;
pub mod util;

// Transpilation modules
pub mod ast_bundle;
pub mod mle_ast;
pub mod scalar_ops;

// Re-export core types
pub use ast_bundle::{Assertion, AstBundle, AstCommitment, TargetField, WitnessType};
pub use mle_ast::{
    get_g1_chunks, set_pending_commitment_chunks, set_pending_g1_chunks,
    set_pending_point_elements, store_g1_chunks, take_pending_commitment_chunks,
    take_pending_g1_chunks, take_pending_point_elements,
};
pub use mle_ast::{DefaultMleAst, MleAst};
// G1 operation arena for BlindFold transpilation
pub use mle_ast::{
    alloc_g1_op, get_g1_op, is_constraint_mode, num_g1_constraints, num_g1_ops,
    register_g1_constraint, take_g1_constraints, take_g1_ops, G1Constraint, G1Op, G1OpId,
    G1_OP_NONE,
};
