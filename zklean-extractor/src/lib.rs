//! zkLean Extractor Library
//!
//! Extracts Jolt verification logic into structured representations
//! for formal verification (Lean4) and circuit transpilation (Gnark).
//!
//! ## Public API
//!
//! This library exposes:
//! - `mle_ast`: MLE AST types and recording field implementation
//! - Other extraction utilities (if needed)

pub mod mle_ast;
pub mod util;

// Re-export commonly used types
pub use mle_ast::{Atom, Edge, MleAst, Node};
