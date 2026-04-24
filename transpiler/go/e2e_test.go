package jolt_verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// getWorkspaceRoot returns the Cargo workspace root (jolt/)
func getWorkspaceRoot() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(currentFile)))
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
	t.Log("--- Step 0: Building Rust binaries ---")
	runCommand(t, "build-fibonacci", root,
		"cargo", "build", "-p", "fibonacci", "--release",
		"--features", "transcript-poseidon",
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler",
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
	t.Log("--- Step 0: Building Rust binaries ---")
	runCommand(t, "build-merkle-tree-save", root,
		"cargo", "build", "-p", "merkle-tree-save", "--release",
		"--features", "transcript-poseidon",
	)
	runCommand(t, "build-transpiler", root,
		"cargo", "build", "-p", "transpiler", "--bin", "transpiler", "--release",
		"--features", "transcript-poseidon",
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
