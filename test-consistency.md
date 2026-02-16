# Testing: Rust/Go Assertion Comparison

## Quick Reference

```bash
# Standard tests (no flags needed)
cd gnark-transpiler/go && go test -v -run TestStages16CircuitSolver

# Debug tests (compare Rust vs Go assertions)
# Step 1: generate debug circuit + Rust assertion JSON
cargo run -p gnark-transpiler --bin transpile_stages -- --debug
cargo run -p gnark-transpiler --bin verify_real --features debug-expected-output

# Step 2: run comparison
cd gnark-transpiler/go && go test -v -tags debug_intermediates -run TestRustGoAssertionMatch
```

## Architecture

The verifier has 15 assertions (equality checks) across stages 1-6.
To compare Rust vs Go, we need both sides to export the concrete values of each assertion.

**Rust side:** `verify_real --features debug-expected-output` runs the real verifier
with a global assertion counter (`jolt-core/src/assertion_debug.rs`) that captures
lhs/rhs at each of the 15 assertion sites. Exports to `go/rust_all_assertions.json`.

**Go side:** `stages16_circuit_debug.go` (generated with `--debug` flag) includes
`api.Println` calls that print lhs/rhs of each assertion during solver execution.
The test captures stdout and parses these values.

**Why two steps?** `transpile_stages` runs the *symbolic* verifier (produces AST, not
concrete values). `verify_real` runs the *real* verifier (produces concrete field
elements). Both need the same proof files in `/tmp/`. A future improvement would be
to embed the real verification inside `transpile_stages --debug` so it's a single command.

## Go Build Tags

Go build tags apply to **entire files** (not individual functions like Rust's `#[cfg]`).
Two circuit files define the same struct/method, selected by tag:

| File | Tag | Content |
|------|-----|---------|
| `stages16_circuit.go` | `!debug_intermediates` | Normal circuit |
| `stages16_circuit_debug.go` | `debug_intermediates` | Circuit + `api.Println` |

Tests in `bitflip_test.go` have `//go:build debug_intermediates` because they need
the debug circuit's `api.Println` output. Tests in `stages16_circuit_test.go` have
no tag and always run against the normal circuit.

## Assertion Map

| # | Source | Rust file | Label |
|---|--------|-----------|-------|
| a0 | check_sum_evals (Stage 1 uni_skip) | unipoly.rs:336 | check_sum_evals |
| a1 | BatchedSumcheck::verify (Stage 1) | sumcheck.rs:273 | sumcheck_verify |
| a2 | check_sum_evals (Stage 2 uni_skip) | unipoly.rs:336 | check_sum_evals |
| a3 | BatchedSumcheck::verify (Stage 2) | sumcheck.rs:273 | sumcheck_verify |
| a4 | BatchedSumcheck::verify (Stage 3) | sumcheck.rs:273 | sumcheck_verify |
| a5 | Rs1 claim consistency | registers/read_write_checking.rs:126 | registers_rs1_consistency |
| a6 | Rs2 claim consistency | registers/read_write_checking.rs:136 | registers_rs2_consistency |
| a7 | Rs1 claim consistency (2nd call) | registers/read_write_checking.rs:126 | registers_rs1_consistency |
| a8 | Rs2 claim consistency (2nd call) | registers/read_write_checking.rs:136 | registers_rs2_consistency |
| a9 | BatchedSumcheck::verify (Stage 4) | sumcheck.rs:273 | sumcheck_verify |
| a10 | Lookup output consistency | instruction_lookups/read_raf_checking.rs:155 | instruction_lookup_consistency |
| a11 | Lookup output consistency (2nd call) | instruction_lookups/read_raf_checking.rs:155 | instruction_lookup_consistency |
| a12 | BatchedSumcheck::verify (Stage 5) | sumcheck.rs:273 | sumcheck_verify |
| a13 | Unexpanded PC consistency | bytecode/read_raf_checking.rs:1107 | bytecode_unexpanded_pc_consistency |
| a14 | BatchedSumcheck::verify (Stage 6) | sumcheck.rs:273 | sumcheck_verify |

Duplicates (a5==a7, a6==a8, a10==a11) are the same expression evaluated twice
by different sumcheck instances. They are redundant but correct constraints.

## Test Inventory

### Debug tests (`bitflip_test.go`, requires `-tags debug_intermediates`)

**TestRustGoAssertionMatch** - Loads `rust_all_assertions.json`, runs Go solver,
compares all 15 lhs/rhs values 1:1 (mod p). This is the definitive Rust==Go test.

**TestBitFlipAvalanche** - Flips 1 bit in 5 witness fields, reports which of the
15 assertions change. Empirical result: 5-7/15 change per field (no full avalanche).

### Standard tests (`stages16_circuit_test.go`, no tag)

**TestStages16CircuitSolver** - Runs solver with real witness. The basic "does it work" test.

**TestStages16CircuitProveVerify** - Full Groth16 prove + verify. The heaviest test (~30s).

**TestCorruptedWitnessRejected** - Corrupts 5 specific fields, verifies all rejected.

**TestRandomFuzzing** - Fuzzes 20 fields at regular intervals, expects >50% rejection rate.

**TestAssertionCountMatchesTheory** - Verifies the circuit has exactly 15 assertions.

**TestCircuitNotTrivial** - Sanity check that constraints > 0 and witness is non-trivial.

## Rust Feature Flags

`debug-expected-output` propagates through: `gnark-transpiler` -> `jolt-core`.
When active, `assertion_debug.rs` compiles and each assertion site calls
`log_assertion_eq()`. When inactive, zero overhead (code doesn't exist).

## Files Changed (vs pre-debug baseline)

| File | Change |
|------|--------|
| `jolt-core/src/assertion_debug.rs` | NEW - global counter + JSON export |
| `jolt-core/src/lib.rs` | `pub mod assertion_debug` (cfg-gated) |
| `jolt-core/src/poly/unipoly.rs` | `log_assertion_eq` at check_sum_evals |
| `jolt-core/src/subprotocols/sumcheck.rs` | Replaced local counter with shared `assertion_debug` |
| `jolt-core/src/zkvm/registers/read_write_checking.rs` | `log_assertion_eq` x2 |
| `jolt-core/src/zkvm/instruction_lookups/read_raf_checking.rs` | `log_assertion_eq` x1 |
| `jolt-core/src/zkvm/bytecode/read_raf_checking.rs` | `log_assertion_eq` x1 |
| `gnark-transpiler/src/bin/verify_real.rs` | Reset + export_json calls |
| `gnark-transpiler/src/bin/transpile_stages.rs` | `--debug` flag for optional debug circuit |
| `gnark-transpiler/src/codegen.rs` | `debug_intermediates` flag + deferred assertions |
| `gnark-transpiler/go/bitflip_test.go` | NEW - TestRustGoAssertionMatch + TestBitFlipAvalanche |
| `gnark-transpiler/go/stages16_circuit_debug.go` | GENERATED - circuit with api.Println |
| `gnark-transpiler/go/rust_all_assertions.json` | GENERATED - 15 assertion values from Rust |
