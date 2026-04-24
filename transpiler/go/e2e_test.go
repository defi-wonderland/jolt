package jolt_verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// getWorkspaceRoot returns the Cargo workspace root (jolt/)
func getWorkspaceRoot() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(currentFile)))
}

// cargoFeatures returns the Cargo feature flags for the current test run.
// Defaults to "transcript-poseidon". Override with JOLT_FEATURES env var
// to test additional features, e.g.:
//
//	JOLT_FEATURES=transcript-poseidon,padded-io go test -run TestEndToEndPipeline -v -timeout 30m
func cargoFeatures() string {
	if f := os.Getenv("JOLT_FEATURES"); f != "" {
		return f
	}
	return "transcript-poseidon"
}

func runCommand(t *testing.T, name string, dir string, bin string, args ...string) time.Duration {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	t.Logf("Running: %s %v", bin, args)
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v", name, err)
	}
	elapsed := time.Since(start)
	t.Logf("%s completed [%v]", name, elapsed)
	return elapsed
}

// TestEndToEndPipeline runs the complete pipeline and reports all timings.
//
// Usage: go test -run TestEndToEndPipeline -v -timeout 30m
func TestEndToEndPipeline(t *testing.T) {
	t.Log("=== End-to-End Pipeline ===")
	root := getWorkspaceRoot()
	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	// Step 0: Build Rust binaries (not timed)
	features := cargoFeatures()
	t.Logf("--- Step 0: Building Rust binaries (features: %s) ---", features)
	runCommand(t, "build-fibonacci", root,
		"cargo", "build", "-p", "fibonacci", "--release",
		"--features", features,
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler",
		"--features", features,
	)
	t.Log("Rust binaries ready")

	totalStart := time.Now()

	// Step 1: Fibonacci proof (binary only, no compilation)
	t.Log("--- Step 1: Fibonacci Proof ---")
	fibBin := filepath.Join(root, "target", "release", "fibonacci")
	fibTime := runCommand(t, "fibonacci", root,
		fibBin, "--save", "50",
	)

	// Step 2: Transpile (binary only, no compilation)
	t.Log("--- Step 2: Transpile ---")
	transpilerBin := filepath.Join(root, "target", "debug", "transpiler")
	transpileTime := runCommand(t, "transpiler", root,
		transpilerBin,
	)

	// Step 3: Groth16 (subprocess to pick up regenerated circuit)
	t.Log("--- Step 3: Groth16 ---")
	groth16Time := runCommand(t, "groth16", goDir,
		"go", "test", "-run", "TestStagesCircuitProveVerify",
		"-v", "-timeout", "25m", "-count=1",
	)

	// Read detailed results written by TestStagesCircuitProveVerify
	resultsPath := filepath.Join(goDir, "groth16_results.json")
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("Failed to read groth16_results.json: %v", err)
	}
	var results map[string]float64
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("Failed to parse groth16_results.json: %v", err)
	}

	totalTime := time.Since(totalStart)
	t.Log("")
	t.Log("========================================")
	t.Log("=== End-to-End Summary ===")
	t.Log("========================================")
	t.Logf("Fibonacci proof (Rust):  %v", fibTime)
	t.Logf("Transpile (Rust):        %v", transpileTime)
	t.Logf("Circuit compile (Go):    %v", time.Duration(results["compile_ms"])*time.Millisecond)
	t.Logf("Groth16 setup (Go):      %v", time.Duration(results["setup_ms"])*time.Millisecond)
	t.Logf("Groth16 prove (Go):      %v", time.Duration(results["prove_ms"])*time.Millisecond)
	t.Logf("Groth16 verify (Go):     %v", time.Duration(results["verify_ms"])*time.Millisecond)
	t.Log("----------------------------------------")
	t.Logf("TOTAL pipeline:          %v", totalTime)
	t.Logf("Groth16 total:           %v", groth16Time)
	t.Logf("Constraints:             %.0f", results["constraints"])
	t.Logf("Proof size:              %.0f bytes", results["proof_bytes"])
	t.Log("========================================")
}

// TestEndToEndMerkleTree runs the complete pipeline for the merkle-tree example,
// which uses TrustedAdvice and UntrustedAdvice. This catches regressions in the
// advice path that the fibonacci E2E cannot detect.
//
// Usage: go test -run TestEndToEndMerkleTree -v -timeout 30m
func TestEndToEndMerkleTree(t *testing.T) {
	t.Log("=== End-to-End Merkle-Tree (with Advice) Pipeline ===")
	root := getWorkspaceRoot()
	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	// Step 0: Build Rust binaries
	features := cargoFeatures()
	t.Logf("--- Step 0: Building Rust binaries (features: %s) ---", features)
	runCommand(t, "build-merkle-tree-save", root,
		"cargo", "build", "-p", "merkle-tree-save", "--release",
		"--features", features,
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler", "--release",
		"--features", features,
	)
	t.Log("Rust binaries ready")

	totalStart := time.Now()

	// Step 1: Generate merkle-tree proof with advice
	t.Log("--- Step 1: Merkle-Tree Proof (with TrustedAdvice) ---")
	merkleBin := filepath.Join(root, "target", "release", "merkle-tree-save")
	merkleTime := runCommand(t, "merkle-tree", root,
		merkleBin, "--save",
	)

	// Step 2: Transpile with trusted advice commitment
	t.Log("--- Step 2: Transpile (with --trusted-advice) ---")
	transpilerBin := filepath.Join(root, "target", "release", "transpiler")
	transpileTime := runCommand(t, "transpiler", root,
		transpilerBin,
		"--proof", "/tmp/merkle_proof.bin",
		"--io-device", "/tmp/merkle_io_device.bin",
		"--trusted-advice", "/tmp/merkle_trusted_advice.bin",
	)

	// Step 3: Groth16 prove + verify (subprocess to pick up regenerated circuit)
	t.Log("--- Step 3: Groth16 ---")
	groth16Time := runCommand(t, "groth16", goDir,
		"go", "test", "-run", "TestStagesCircuitProveVerify",
		"-v", "-timeout", "25m", "-count=1",
	)

	// Read detailed results written by TestStagesCircuitProveVerify
	resultsPath := filepath.Join(goDir, "groth16_results.json")
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("Failed to read groth16_results.json: %v", err)
	}
	var results map[string]float64
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("Failed to parse groth16_results.json: %v", err)
	}

	totalTime := time.Since(totalStart)
	t.Log("")
	t.Log("========================================")
	t.Log("=== Merkle-Tree E2E Summary ===")
	t.Log("========================================")
	t.Logf("Merkle-tree proof (Rust): %v", merkleTime)
	t.Logf("Transpile (Rust):         %v", transpileTime)
	t.Logf("Circuit compile (Go):     %v", time.Duration(results["compile_ms"])*time.Millisecond)
	t.Logf("Groth16 setup (Go):       %v", time.Duration(results["setup_ms"])*time.Millisecond)
	t.Logf("Groth16 prove (Go):       %v", time.Duration(results["prove_ms"])*time.Millisecond)
	t.Logf("Groth16 verify (Go):      %v", time.Duration(results["verify_ms"])*time.Millisecond)
	t.Log("----------------------------------------")
	t.Logf("TOTAL pipeline:           %v", totalTime)
	t.Logf("Groth16 total:            %v", groth16Time)
	t.Logf("Constraints:              %.0f", results["constraints"])
	t.Logf("Proof size:               %.0f bytes", results["proof_bytes"])
	t.Log("========================================")
}

// runExamplePipeline is the generic end-to-end driver for examples that wire
// `--save` to produce /tmp/<name>_proof.bin and /tmp/<name>_io_device.bin.
//
// Callers pass the cargo package name, the in-tree binary name (usually the
// same), the prefix used for the saved artifacts, and any extra args for the
// example binary after `--save` (e.g. fibonacci needs "50").
func runExamplePipeline(t *testing.T, pkg, bin, prefix string, binArgs ...string) {
	t.Helper()
	t.Logf("=== End-to-End %s Pipeline ===", pkg)
	root := getWorkspaceRoot()
	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	t.Logf("--- Step 0: Building Rust binaries (%s) ---", pkg)
	runCommand(t, "build-"+pkg, root,
		"cargo", "build", "-p", pkg, "--release",
		"--features", "transcript-poseidon",
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler",
	)
	t.Log("Rust binaries ready")

	totalStart := time.Now()

	t.Logf("--- Step 1: %s Proof ---", pkg)
	exampleBin := filepath.Join(root, "target", "release", bin)
	exampleTime := runCommand(t, pkg, root,
		exampleBin, append([]string{"--save"}, binArgs...)...,
	)

	t.Log("--- Step 2: Transpile ---")
	transpilerBin := filepath.Join(root, "target", "debug", "transpiler")
	transpileTime := runCommand(t, "transpiler", root,
		transpilerBin,
		"--proof", fmt.Sprintf("/tmp/%s_proof.bin", prefix),
		"--io-device", fmt.Sprintf("/tmp/%s_io_device.bin", prefix),
	)

	t.Log("--- Step 3: Groth16 ---")
	groth16Time := runCommand(t, "groth16", goDir,
		"go", "test", "-run", "TestStagesCircuitProveVerify",
		"-v", "-timeout", "25m", "-count=1",
	)

	resultsPath := filepath.Join(goDir, "groth16_results.json")
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("Failed to read groth16_results.json: %v", err)
	}
	var results map[string]float64
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("Failed to parse groth16_results.json: %v", err)
	}

	totalTime := time.Since(totalStart)
	t.Log("")
	t.Log("========================================")
	t.Logf("=== %s E2E Summary ===", pkg)
	t.Log("========================================")
	t.Logf("%s proof (Rust):     %v", pkg, exampleTime)
	t.Logf("Transpile (Rust):        %v", transpileTime)
	t.Logf("Circuit compile (Go):    %v", time.Duration(results["compile_ms"])*time.Millisecond)
	t.Logf("Groth16 setup (Go):      %v", time.Duration(results["setup_ms"])*time.Millisecond)
	t.Logf("Groth16 prove (Go):      %v", time.Duration(results["prove_ms"])*time.Millisecond)
	t.Logf("Groth16 verify (Go):     %v", time.Duration(results["verify_ms"])*time.Millisecond)
	t.Log("----------------------------------------")
	t.Logf("TOTAL pipeline:          %v", totalTime)
	t.Logf("Groth16 total:           %v", groth16Time)
	t.Logf("Constraints:             %.0f", results["constraints"])
	t.Logf("Proof size:              %.0f bytes", results["proof_bytes"])
	t.Log("========================================")
}

// TestEndToEndMuldiv runs the E2E pipeline for the muldiv example.
// Usage: go test -run TestEndToEndMuldiv -v -timeout 30m
func TestEndToEndMuldiv(t *testing.T) {
	runExamplePipeline(t, "muldiv", "muldiv", "muldiv")
}

// TestEndToEndCollatz runs the E2E pipeline for the collatz example.
// Usage: go test -run TestEndToEndCollatz -v -timeout 30m
func TestEndToEndCollatz(t *testing.T) {
	runExamplePipeline(t, "collatz", "collatz", "collatz")
}

// TestEndToEndModinv runs the E2E pipeline for the modinv example.
// Usage: go test -run TestEndToEndModinv -v -timeout 30m
func TestEndToEndModinv(t *testing.T) {
	runExamplePipeline(t, "modinv", "modinv", "modinv")
}

// TestEndToEndSha3 runs the E2E pipeline for the sha3-ex example.
// Usage: go test -run TestEndToEndSha3 -v -timeout 30m
func TestEndToEndSha3(t *testing.T) {
	runExamplePipeline(t, "sha3-ex", "sha3-ex", "sha3")
}

// TestCrossWitnessSoundness verifies that a witness from one program CANNOT produce
// a valid Groth16 proof for a different program using the same universal circuit.
// This is the core soundness property: shared pk/vk does not allow cross-program forgery.
//
// Usage: go test -run TestCrossWitnessSoundness -v -timeout 30m
func TestCrossWitnessSoundness(t *testing.T) {
	t.Log("=== Cross-Witness Soundness Test ===")
	root := getWorkspaceRoot()
	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	// Step 0: Build Rust binaries
	features := cargoFeatures()
	t.Logf("--- Step 0: Building Rust binaries (features: %s) ---", features)
	runCommand(t, "build-fibonacci", root,
		"cargo", "build", "-p", "fibonacci", "--release",
		"--features", features+",padded-io",
	)
	runCommand(t, "build-muldiv", root,
		"cargo", "build", "-p", "muldiv", "--release",
		"--features", features+",padded-io",
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler",
		"--features", features+",padded-io",
	)

	fibBin := filepath.Join(root, "target", "release", "fibonacci")
	muldivBin := filepath.Join(root, "target", "release", "muldiv")
	transpilerBin := filepath.Join(root, "target", "debug", "transpiler")

	// Clean stale class directories
	for _, name := range []string{"class_S", "class_M", "class_L", "class_XL"} {
		os.RemoveAll(filepath.Join(goDir, name))
	}

	// Step 1: Generate fib witness
	t.Log("--- Step 1: Generate fibonacci witness ---")
	runCommand(t, "fib", root, fibBin, "--save", "50")
	runCommand(t, "transpile-fib", root, transpilerBin)

	// Find class directory
	classDir := ""
	for _, name := range []string{"class_S", "class_M", "class_L", "class_XL"} {
		candidate := filepath.Join(goDir, name)
		if _, err := os.Stat(filepath.Join(candidate, "stages_circuit.go")); err == nil {
			classDir = candidate
			t.Logf("  Class directory: %s", name)
			break
		}
	}
	if classDir == "" {
		t.Fatal("No class directory found after transpiling fibonacci")
	}

	// Save fib witness separately
	fibWitnessPath := filepath.Join(classDir, "fib_witness.json")
	fibWitness, err := os.ReadFile(filepath.Join(classDir, "stages_witness.json"))
	if err != nil {
		t.Fatalf("Failed to read fib witness: %v", err)
	}
	if err := os.WriteFile(fibWitnessPath, fibWitness, 0644); err != nil {
		t.Fatalf("Failed to save fib witness: %v", err)
	}
	t.Logf("  Saved fib witness: %d bytes", len(fibWitness))

	// Step 2: Generate muldiv witness (overwrites circuit + witness in class dir)
	t.Log("--- Step 2: Generate muldiv witness ---")
	runCommand(t, "muldiv", root, muldivBin, "--save")
	runCommand(t, "transpile-muldiv", root, transpilerBin,
		"--proof", "/tmp/muldiv_proof.bin",
		"--io-device", "/tmp/muldiv_io_device.bin",
		"--preprocessing", "/tmp/muldiv_preprocessing.dat",
	)
	muldivWitnessPath := filepath.Join(classDir, "stages_witness.json")

	// Step 3: Compile circuit + setup
	t.Log("--- Step 3: Compile circuit + Groth16 setup ---")
	var circuit JoltStagesCircuit
	compiledR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	t.Logf("  Compiled: %d constraints", compiledR1cs.GetNbConstraints())

	// Delete cached pk/vk to force fresh setup for this circuit
	os.Remove(filepath.Join(classDir, "proving_key.bin"))
	os.Remove(filepath.Join(classDir, "verifying_key.bin"))

	pk, vk, setupTime, _ := cachedSetup(t, compiledR1cs, classDir)
	t.Logf("  Setup complete [%v]", setupTime)

	// Step 4: Prove with CORRECT witness (muldiv) — must succeed
	t.Log("--- Step 4: Prove with correct witness (muldiv) ---")
	correctAssignment, err := LoadStagesAssignment(muldivWitnessPath)
	if err != nil {
		t.Fatalf("Failed to load muldiv witness: %v", err)
	}
	correctWitness, err := frontend.NewWitness(correctAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create correct witness: %v", err)
	}
	proof, err := groth16.Prove(compiledR1cs, pk, correctWitness)
	if err != nil {
		t.Fatalf("FAIL: correct witness should prove successfully: %v", err)
	}
	publicWitness, err := correctWitness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("FAIL: correct witness should verify successfully: %v", err)
	}
	t.Log("  Correct witness: prove + verify PASSED")

	// Step 5: Both programs' witnesses are VALID for the universal circuit (expected).
	// The circuit verifies "this Jolt proof is internally consistent" — both programs
	// produce valid proofs. What distinguishes them are the public inputs (bytecode
	// words, I/O values, commitments). A smart contract verifier would check that
	// those match the expected program.
	t.Log("--- Step 5: Verify fib witness is also valid (universal circuit) ---")
	fibAssignment, err := LoadStagesAssignment(fibWitnessPath)
	if err != nil {
		t.Fatalf("Failed to load fib witness: %v", err)
	}
	fibWit, err := frontend.NewWitness(fibAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create fib witness: %v", err)
	}
	fibProof, err := groth16.Prove(compiledR1cs, pk, fibWit)
	if err != nil {
		t.Fatalf("FAIL: fib witness should also be valid for universal circuit: %v", err)
	}
	fibPub, err := fibWit.Public()
	if err != nil {
		t.Fatalf("Failed to get fib public witness: %v", err)
	}
	err = groth16.Verify(fibProof, vk, fibPub)
	if err != nil {
		t.Fatalf("FAIL: fib proof should verify with universal vk: %v", err)
	}
	t.Log("  Fib witness: prove + verify PASSED (both programs valid, as expected)")

	// Step 6: Prove that a CORRUPTED witness fails — this is the real soundness check.
	// Flip one commitment value. The circuit constraints will not be satisfied.
	t.Log("--- Step 6: Prove with CORRUPTED witness (one value flipped) ---")
	corruptedAssignment, err := LoadStagesAssignment(muldivWitnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness for corruption: %v", err)
	}

	// Corrupt the first commitment field via reflection
	rv := reflect.ValueOf(corruptedAssignment).Elem()
	rt := rv.Type()
	corrupted := false
	for i := 0; i < rv.NumField(); i++ {
		name := rt.Field(i).Name
		if len(name) > 10 && name[:10] == "Commitment" {
			field := rv.Field(i)
			if field.IsValid() && field.CanSet() && !field.IsNil() {
				// Flip: replace value with value+1
				orig := field.Interface().(*big.Int)
				flipped := new(big.Int).Add(orig, big.NewInt(1))
				field.Set(reflect.ValueOf(flipped))
				t.Logf("  Corrupted field: %s", name)
				corrupted = true
				break
			}
		}
	}
	if !corrupted {
		t.Fatal("Failed to find a Commitment field to corrupt")
	}

	corruptedWitness, err := frontend.NewWitness(corruptedAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create corrupted witness: %v", err)
	}
	_, err = groth16.Prove(compiledR1cs, pk, corruptedWitness)
	if err == nil {
		t.Fatal("SOUNDNESS VIOLATION: corrupted witness should have failed to prove!")
	}
	t.Logf("  Corrupted witness: prove correctly REJECTED: %v", err)

	// Step 7: Cross-verify fails — fib proof cannot verify with muldiv public inputs
	t.Log("--- Step 7: Cross-verify (fib proof vs muldiv public inputs) ---")
	err = groth16.Verify(fibProof, vk, publicWitness)
	if err == nil {
		t.Fatal("SOUNDNESS VIOLATION: fib proof should not verify with muldiv public inputs!")
	}
	t.Logf("  Cross-verify correctly REJECTED: %v", err)

	t.Log("")
	t.Log("========================================")
	t.Log("=== Cross-Witness Soundness: PASSED ===")
	t.Log("========================================")
}

// loadWitnessMap is a helper to load raw witness JSON
func loadWitnessMap(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}
	return m, nil
}

// TestSizeClassCrossProgram verifies that two DIFFERENT programs (fibonacci and muldiv)
// produce BYTE-IDENTICAL circuits via automatic size class selection.
//
// Neither binary uses --class: the macro-generated preprocess_shared_X() auto-selects
// the smallest class that fits the program. Both small programs land in the same class,
// producing identical circuits that share a single Groth16 trusted setup (pk, vk).
//
// What this test verifies:
//   - Auto class selection works (no --class flag needed)
//   - Circuits are byte-identical (same Go code, byte for byte)
//   - Witnesses have the same variable names but different values
//
// Usage: go test -run TestSizeClassCrossProgram -v -timeout 30m
func TestSizeClassCrossProgram(t *testing.T) {
	t.Log("=== Universal Circuit Test (fib vs muldiv, auto class) ===")
	root := getWorkspaceRoot()
	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	// Step 0: Build Rust binaries
	t.Log("--- Building Rust binaries ---")
	runCommand(t, "build-fibonacci", root,
		"cargo", "build", "-p", "fibonacci", "--release",
		"--features", "transcript-poseidon,padded-io",
	)
	runCommand(t, "build-muldiv", root,
		"cargo", "build", "-p", "muldiv", "--release",
		"--features", "transcript-poseidon,padded-io",
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler",
		"--features", "transcript-poseidon,padded-io",
	)

	fibBin := filepath.Join(root, "target", "release", "fibonacci")
	muldivBin := filepath.Join(root, "target", "release", "muldiv")
	transpilerBin := filepath.Join(root, "target", "debug", "transpiler")

	// Clean stale class directories from previous runs
	for _, name := range []string{"class_S", "class_M", "class_L", "class_XL"} {
		os.RemoveAll(filepath.Join(goDir, name))
	}

	// Step 1: fib(50) → auto-selects size class → transpile
	// No --class flag: the macro-generated preprocess_shared_fib() auto-selects
	// the smallest class that fits the program.
	t.Log("--- Run A: fibonacci (auto class) ---")
	runCommand(t, "fib", root, fibBin, "--save", "50")
	runCommand(t, "transpile-fib", root, transpilerBin)

	// Find which class directory was created
	classDir := ""
	for _, name := range []string{"class_S", "class_M", "class_L", "class_XL"} {
		candidate := filepath.Join(goDir, name)
		if _, err := os.Stat(filepath.Join(candidate, "stages_circuit.go")); err == nil {
			classDir = candidate
			t.Logf("  Auto-detected class directory: %s", name)
			break
		}
	}
	if classDir == "" {
		t.Fatal("No class directory found after transpiling fibonacci")
	}

	circuitA, err := os.ReadFile(filepath.Join(classDir, "stages_circuit.go"))
	if err != nil {
		t.Fatalf("Failed to read fib circuit: %v", err)
	}
	witnessAraw, err := os.ReadFile(filepath.Join(classDir, "stages_witness.json"))
	if err != nil {
		t.Fatalf("Failed to read fib witness: %v", err)
	}
	linesA := bytes.Count(circuitA, []byte("\n"))
	t.Logf("fib:    circuit=%d bytes (%d lines), witness=%d bytes", len(circuitA), linesA, len(witnessAraw))

	// Step 2: muldiv → auto-selects same class → transpile
	t.Log("--- Run B: muldiv (auto class) ---")
	runCommand(t, "muldiv", root, muldivBin, "--save")
	runCommand(t, "transpile-muldiv", root, transpilerBin,
		"--proof", "/tmp/muldiv_proof.bin",
		"--io-device", "/tmp/muldiv_io_device.bin",
		"--preprocessing", "/tmp/muldiv_preprocessing.dat",
	)

	circuitB, err := os.ReadFile(filepath.Join(classDir, "stages_circuit.go"))
	if err != nil {
		t.Fatalf("Failed to read muldiv circuit: %v", err)
	}
	witnessBraw, err := os.ReadFile(filepath.Join(classDir, "stages_witness.json"))
	if err != nil {
		t.Fatalf("Failed to read muldiv witness: %v", err)
	}
	linesB := bytes.Count(circuitB, []byte("\n"))
	t.Logf("muldiv: circuit=%d bytes (%d lines), witness=%d bytes", len(circuitB), linesB, len(witnessBraw))

	// --- Byte-identity comparison ---
	t.Log("--- Comparing ---")

	// 1. Circuits must be byte-identical (universal circuit)
	if !bytes.Equal(circuitA, circuitB) {
		t.Fatalf("FAIL: circuits are NOT byte-identical (fib=%d bytes, muldiv=%d bytes)", len(circuitA), len(circuitB))
	}
	t.Logf("  circuits: BYTE-IDENTICAL (%d bytes, %d lines)", len(circuitA), linesA)

	// 2. Parse witness keys
	var witnessA, witnessB map[string]string
	if err := json.Unmarshal(witnessAraw, &witnessA); err != nil {
		t.Fatalf("Failed to parse fib witness: %v", err)
	}
	if err := json.Unmarshal(witnessBraw, &witnessB); err != nil {
		t.Fatalf("Failed to parse muldiv witness: %v", err)
	}

	// 3. Same set of witness variable names (same symbolic layout)
	if len(witnessA) != len(witnessB) {
		t.Fatalf("FAIL: witness variable counts differ: fib=%d vs muldiv=%d", len(witnessA), len(witnessB))
	}
	for key := range witnessA {
		if _, ok := witnessB[key]; !ok {
			t.Fatalf("FAIL: witness key %q present in fib but missing in muldiv", key)
		}
	}
	t.Logf("  witnesses: same variable names (%d vars)", len(witnessA))

	// 4. Witness values must differ (different programs produce different proof data)
	diffCount := 0
	for key, valA := range witnessA {
		if valB := witnessB[key]; valA != valB {
			diffCount++
		}
	}
	if diffCount == 0 {
		t.Fatal("FAIL: all witness values are identical — two different programs should not produce identical witnesses")
	}
	t.Logf("  witnesses: %d/%d values differ (as expected)", diffCount, len(witnessA))

	t.Log("")
	t.Log("========================================")
	t.Log("=== Cross-Program Universality: PASSED ===")
	t.Log("========================================")
}
