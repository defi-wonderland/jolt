# Jolt Transpiler — Claude Code Context

## What is this

Transpilation pipeline: Jolt zkVM verifier → Gnark/Groth16 circuits (BN254).

The Rust verifier runs with `MleAst` (symbolic field type) instead of real field elements. Every arithmetic operation builds an AST. That AST gets converted to Go/gnark circuit code.

## Current state

- **Stages 1-7** (all sumchecks): transpiled, 3.1M constraints, Groth16 prove+verify passes
- **Stage 8** (PCS/Hyrax): hand-written in Go (native Grumpkin curve ops)
- **Transcript**: Poseidon only (`--features transcript-poseidon`)

## Quick start

```bash
# Generate proof
cargo run -p fibonacci --release --features transcript-poseidon -- --save 50

# Transpile
cargo run -p transpiler --bin transpiler --release

# Test (the real test — Groth16 prove + verify)
cd transpiler/go && go test -v -run TestStagesCircuitProveVerify
```

## Key files

| File | What |
|------|------|
| `transpiler/src/main.rs` | Entry point: load proof → symbolize → verify → codegen |
| `transpiler/src/gnark_codegen.rs` | AST → Go code |
| `transpiler/src/symbolic_traits/poseidon.rs` | PoseidonAstTranscript (Fiat-Shamir) |
| `transpiler/src/symbolic_traits/opening_accumulator.rs` | MleOpeningAccumulator |
| `transpiler/src/symbolic_proof.rs` | VarAllocator, witness capture |
| `zklean-extractor/src/mle_ast.rs` | MleAst type, Node enum, AstBundle |
| `jolt-core/src/zkvm/transpilable_verifier.rs` | Generic verifier (stages 1-7) |
| `jolt-core/src/transcripts/poseidon.rs` | Concrete Poseidon transcript |
| `jolt-core/src/transcripts/blake2b.rs` | Concrete Blake2b transcript |
| `jolt-core/src/transcripts/transcript.rs` | Transcript trait definition |
| `transpiler/go/stages_circuit.go` | Generated gnark circuit |
| `transpiler/go/poseidon/poseidon.go` | Poseidon Go implementation |

## Critical rules

1. **NEVER TWO PATHS, ALWAYS GENERICS** — same code for real verification and symbolic transpilation, via Rust generics
2. **Transcript must match exactly** — gnark circuit produces same Fiat-Shamir challenges as Rust verifier, byte for byte
3. **Ask before making changes** — explain the plan, wait for approval
4. **No Co-Authored-By** in commits
5. **GPG signing required** — use `git add` and provide commit message for user to execute

## Detailed documentation

All detailed docs live in `../JoltContext/`. Start with [CLAUDE.md](../JoltContext/CLAUDE.md).

| What | Where |
|------|-------|
| Project overview + doc index | [JoltContext/CLAUDE.md](../JoltContext/CLAUDE.md) |
| Transpilation architecture | [JoltContext/theory/ASTContext.md](../JoltContext/theory/ASTContext.md) |
| Poseidon transcript guide | [JoltContext/guides/fr-transcript-poseidon.md](../JoltContext/guides/fr-transcript-poseidon.md) |
| Task list | [JoltContext/tasks/](../JoltContext/tasks/) |
| **009: Blake2b + AST generalization** | [JoltContext/tasks/009-add-blake2b-transcript-transpilation.md](../JoltContext/tasks/009-add-blake2b-transcript-transpilation.md) |
| **009: Detailed implementation guide** | [.claude/guides/009-blake2b-detailed-implementation.md](guides/009-blake2b-detailed-implementation.md) |

## Open tasks

| ID | Task | Priority |
|----|------|----------|
| 009 | Blake2b transcript + generalize AST (absorbs 003) | Medium |
| 008 | Add tests across transpilation pipeline | High |
| 005 | Simplify witness extraction | Low |
| 006 | Remove unused jolt-core dependencies | Low |

---
*Last updated: February 17, 2026*
