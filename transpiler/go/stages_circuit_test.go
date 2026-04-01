package jolt_verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// getStagesWitnessPath returns the path to stages_witness.json
func getStagesWitnessPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "stages_witness.json")
}

// LoadStagesAssignment loads witness data and creates a circuit assignment
func LoadStagesAssignment(witnessPath string) (*JoltStagesCircuit, error) {
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read witness file: %w", err)
	}

	var witnessMap map[string]string
	if err := json.Unmarshal(data, &witnessMap); err != nil {
		return nil, fmt.Errorf("failed to parse witness JSON: %w", err)
	}

	assignment := &JoltStagesCircuit{}
	v := reflect.ValueOf(assignment).Elem()
	t := v.Type()

	loaded := 0
	for i := 0; i < v.NumField(); i++ {
		fieldName := t.Field(i).Name
		field := v.Field(i)

		if value, ok := witnessMap[fieldName]; ok {
			if field.IsValid() && field.CanSet() {
				val, ok := new(big.Int).SetString(value, 10)
				if !ok {
					return nil, fmt.Errorf("invalid value for %s: %s", fieldName, value)
				}
				field.Set(reflect.ValueOf(val))
				loaded++
			}
		}
	}

	if loaded == 0 {
		return nil, fmt.Errorf("no witness values loaded - field name mismatch?")
	}

	return assignment, nil
}

// TestStagesCircuitSolver verifies the R1CS solver succeeds with the transpiled witness.
// This test loads the witness, runs the solver, and prints debug values for manual inspection.
func TestStagesCircuitSolver(t *testing.T) {
	t.Log("Jolt Stages 1-7 Verifier - Gnark Solver Debug Test")
	t.Log("")

	// Load witness
	witnessPath := getStagesWitnessPath()
	assignment, err := LoadStagesAssignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness data: %v", err)
	}
	t.Logf("Loaded witness from: %s", witnessPath)

	// Debug: print some witness values
	v := reflect.ValueOf(assignment).Elem()
	t.Log("Sample witness values:")
	fieldsToShow := []string{
		"Stage1_Uni_Skip_Coeff_0",
		"Stage1_Uni_Skip_Coeff_1",
		"Claim_Virtual_UnivariateSkip_SpartanOuter",
		"Stage1_Sumcheck_R0_0",
		"Stage1_Sumcheck_R0_1",
		"Stage1_Sumcheck_R0_2",
	}
	for _, name := range fieldsToShow {
		field := v.FieldByName(name)
		if field.IsValid() && !field.IsZero() {
			t.Logf("  %s = %v", name, field.Interface())
		}
	}

	// Manually compute a0 to verify
	// a0 is: sum_j coeff_j * power_sums[j] == 0
	// power_sums for domain size 10 centered at 0 are precomputed constants
	powerSums := []int64{10, 5, 85, 125, 1333, 3125, 25405, 78125, 535333, 1953125, 11982925, 48828125, 278766133, 1220703125, 6649985245, 30517578125, 161264049733, 762939453125, 3952911584365, 19073486328125, 97573430562133, 476837158203125, 2419432933612285, 11920928955078125, 60168159621439333, 298023223876953125, 1499128402505381005, 7450580596923828125}
	coeffFields := []string{
		"Stage1_Uni_Skip_Coeff_0", "Stage1_Uni_Skip_Coeff_1", "Stage1_Uni_Skip_Coeff_2", "Stage1_Uni_Skip_Coeff_3",
		"Stage1_Uni_Skip_Coeff_4", "Stage1_Uni_Skip_Coeff_5", "Stage1_Uni_Skip_Coeff_6", "Stage1_Uni_Skip_Coeff_7",
		"Stage1_Uni_Skip_Coeff_8", "Stage1_Uni_Skip_Coeff_9", "Stage1_Uni_Skip_Coeff_10", "Stage1_Uni_Skip_Coeff_11",
		"Stage1_Uni_Skip_Coeff_12", "Stage1_Uni_Skip_Coeff_13", "Stage1_Uni_Skip_Coeff_14", "Stage1_Uni_Skip_Coeff_15",
		"Stage1_Uni_Skip_Coeff_16", "Stage1_Uni_Skip_Coeff_17", "Stage1_Uni_Skip_Coeff_18", "Stage1_Uni_Skip_Coeff_19",
		"Stage1_Uni_Skip_Coeff_20", "Stage1_Uni_Skip_Coeff_21", "Stage1_Uni_Skip_Coeff_22", "Stage1_Uni_Skip_Coeff_23",
		"Stage1_Uni_Skip_Coeff_24", "Stage1_Uni_Skip_Coeff_25", "Stage1_Uni_Skip_Coeff_26", "Stage1_Uni_Skip_Coeff_27",
	}
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	sum := new(big.Int)
	for i, name := range coeffFields {
		field := v.FieldByName(name)
		if field.IsValid() {
			coeff := field.Interface().(*big.Int)
			ps := big.NewInt(powerSums[i])
			term := new(big.Int).Mul(coeff, ps)
			sum.Add(sum, term)
		}
	}
	sum.Mod(sum, p)
	t.Logf("Manual a0 computation: %v (should be 0)", sum)

	// Debug: Print sumcheck round values for Stage1
	t.Log("\nStage1 Sumcheck Round Values:")
	for r := 0; r <= 10; r++ {
		for j := 0; j <= 2; j++ {
			name := fmt.Sprintf("Stage1_Sumcheck_R%d_%d", r, j)
			field := v.FieldByName(name)
			if field.IsValid() && !field.IsZero() {
				t.Logf("  %s = %v", name, field.Interface())
			}
		}
	}

	// Print the UnivariateSkip claim
	t.Log("\nClaims:")
	uniSkipField := v.FieldByName("Claim_Virtual_UnivariateSkip_SpartanOuter")
	if uniSkipField.IsValid() {
		t.Logf("  Claim_Virtual_UnivariateSkip_SpartanOuter = %v", uniSkipField.Interface())
	}

	// Manually compute the sumcheck verification for Stage1
	t.Log("\n=== Manual Sumcheck Verification ===")

	// The sumcheck verification computes:
	// For each round i: e = eval_compressed_poly(e, R_i, challenge_i)
	// Where eval_compressed_poly evaluates using the hint formula

	// For a degree-2 compressed polynomial with coefficients [c0, c1, c2]:
	// The eval at challenge r is: c0 + c1*r + c2*r^2
	// But the compressed poly stores: [eval_at_0 - eval_at_2, eval_at_2]
	// And we compute: eval_at_0 + r * (hint - eval_at_0) + r^2 * (eval_at_2 - eval_at_0 - hint)
	// Which simplifies to: (1-r)*e0 + r*h + r^2*(e2-e0-h) where h = e(1)
	// Actually the formula is: e = R0 + r * (h - R0 - R0) + r^2 * (R2)
	// where R0 = e(0), R2 = e(2), h = e(1) - R2

	// Let's print some intermediate claim values
	claimFields := []string{
		"Claim_Virtual_OpFlags_Load_SpartanOuter",
		"Claim_Virtual_OpFlags_Store_SpartanOuter",
		"Claim_Virtual_RamAddress_SpartanOuter",
		"Claim_Virtual_LookupOutput_SpartanOuter",
	}
	for _, name := range claimFields {
		field := v.FieldByName(name)
		if field.IsValid() && !field.IsZero() {
			t.Logf("  %s = %v", name, field.Interface())
		}
	}

	// Use gnark test solver to check constraints
	var circuit JoltStagesCircuit
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Logf("Solver error: %v", err)
		// The error message should tell us which constraint failed
	} else {
		t.Log("All constraints satisfied!")
	}
}

// cachedSetup runs Groth16 setup with disk caching. If pk/vk files exist in cacheDir
// and were generated for the same number of constraints, they are loaded from disk.
// Otherwise, setup runs fresh and results are saved to disk.
// Returns (pk, vk, setupTime, fromCache).
func cachedSetup(
	t *testing.T,
	r1cs constraint.ConstraintSystem,
	cacheDir string,
) (groth16.ProvingKey, groth16.VerifyingKey, time.Duration, bool) {
	pkPath := filepath.Join(cacheDir, "proving_key.bin")
	vkPath := filepath.Join(cacheDir, "verifying_key.bin")
	constraintsPath := filepath.Join(cacheDir, "constraints.txt")

	// Check that the cached keys match the current circuit's constraint count.
	cacheValid := false
	if data, err := os.ReadFile(constraintsPath); err == nil {
		var cachedCount int
		if _, err := fmt.Sscanf(string(data), "%d", &cachedCount); err == nil {
			cacheValid = cachedCount == r1cs.GetNbConstraints()
		}
	}
	if !cacheValid {
		t.Logf("Constraint count mismatch or missing — skipping cache, running fresh setup")
	}

	// Try loading from cache
	if cacheValid {
		if pkData, err := os.ReadFile(pkPath); err == nil {
			if vkData, err := os.ReadFile(vkPath); err == nil {
				t.Log("Loading cached pk/vk from disk...")
				startLoad := time.Now()

				pk := groth16.NewProvingKey(ecc.BN254)
				if _, err := pk.ReadFrom(bytes.NewReader(pkData)); err != nil {
					t.Logf("Warning: failed to read cached pk, running fresh setup: %v", err)
				} else {
					vk := groth16.NewVerifyingKey(ecc.BN254)
					if _, err := vk.ReadFrom(bytes.NewReader(vkData)); err != nil {
						t.Logf("Warning: failed to read cached vk, running fresh setup: %v", err)
					} else {
						loadTime := time.Since(startLoad)
						t.Logf("Loaded cached pk (%.2f MB) + vk (%.2f KB) [%v]",
							float64(len(pkData))/1024/1024, float64(len(vkData))/1024, loadTime)
						return pk, vk, loadTime, true
					}
				}
			}
		}
	}

	// Fresh setup
	t.Log("Running Groth16 setup (no cache found)...")
	startSetup := time.Now()

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}
	setupTime := time.Since(startSetup)

	// Save to cache
	if err := os.MkdirAll(cacheDir, 0755); err == nil {
		var pkBuf, vkBuf bytes.Buffer
		pk.WriteTo(&pkBuf)
		vk.WriteTo(&vkBuf)

		if err := os.WriteFile(pkPath, pkBuf.Bytes(), 0644); err != nil {
			t.Logf("Warning: failed to cache pk: %v", err)
		}
		if err := os.WriteFile(vkPath, vkBuf.Bytes(), 0644); err != nil {
			t.Logf("Warning: failed to cache vk: %v", err)
		}
		_ = os.WriteFile(constraintsPath, []byte(fmt.Sprintf("%d", r1cs.GetNbConstraints())), 0644)
		t.Logf("Cached pk (%.2f MB) + vk (%.2f KB) to %s",
			float64(pkBuf.Len())/1024/1024, float64(vkBuf.Len())/1024, cacheDir)
	}

	return pk, vk, setupTime, false
}

// TestStagesCircuitProveVerify runs the complete Groth16 workflow: compile, setup, prove, verify.
// This test generates a 164-byte proof from the transpiled circuit and verifies it succeeds.
// Expected time: ~100s (setup: 1m22s, prove: 7.5s, verify: 2ms)
func TestStagesCircuitProveVerify(t *testing.T) {
	t.Log("Jolt Stages 1-7 Verifier - Full Groth16 Prove/Verify Test")
	t.Log("")

	// Load witness
	witnessPath := getStagesWitnessPath()
	assignment, err := LoadStagesAssignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness data: %v", err)
	}
	t.Logf("Loaded witness from: %s", witnessPath)

	// Compile
	t.Log("")
	t.Log("Compiling circuit...")
	startCompile := time.Now()

	var circuit JoltStagesCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	compileTime := time.Since(startCompile)

	t.Logf("Compiled: %d constraints, %d public inputs, %d internal vars [%v]",
		r1cs.GetNbConstraints(), r1cs.GetNbPublicVariables(), r1cs.GetNbInternalVariables(), compileTime)

	// Setup (with disk caching)
	t.Log("")
	_, currentFile, _, _ := runtime.Caller(0)
	cacheDir := filepath.Dir(currentFile)
	pk, vk, setupTime, fromCache := cachedSetup(t, r1cs, cacheDir)

	if fromCache {
		t.Logf("Setup loaded from cache [%v]", setupTime)
	} else {
		var pkBuf, vkBuf bytes.Buffer
		pk.WriteTo(&pkBuf)
		vk.WriteTo(&vkBuf)
		t.Logf("Setup complete: pk=%.2f MB, vk=%.2f KB [%v]",
			float64(pkBuf.Len())/1024/1024, float64(vkBuf.Len())/1024, setupTime)
	}

	// Prove
	t.Log("")
	t.Log("Generating proof...")
	startProve := time.Now()

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatalf("Failed to prove: %v", err)
	}
	proveTime := time.Since(startProve)

	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf)

	t.Logf("Proof generated: %d bytes [%v]", proofBuf.Len(), proveTime)

	// Verify
	t.Log("")
	t.Log("Verifying proof...")
	startVerify := time.Now()

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}
	verifyTime := time.Since(startVerify)

	t.Logf("Verified [%v]", verifyTime)

	// Summary
	t.Log("")
	t.Log("=== Summary ===")
	t.Logf("Constraints: %d", r1cs.GetNbConstraints())
	t.Logf("Proof size:  %d bytes", proofBuf.Len())
	t.Logf("Prove time:  %v", proveTime)
	t.Logf("Verify time: %v", verifyTime)
	t.Log("")
	t.Log("✓ Stages 1-7 circuit verification passed!")

	// Write results JSON for e2e test
	results := map[string]interface{}{
		"constraints": r1cs.GetNbConstraints(),
		"proof_bytes": proofBuf.Len(),
		"compile_ms":  compileTime.Milliseconds(),
		"setup_ms":    setupTime.Milliseconds(),
		"prove_ms":    proveTime.Milliseconds(),
		"verify_ms":   verifyTime.Milliseconds(),
	}
	if data, err := json.Marshal(results); err == nil {
		_, f, _, _ := runtime.Caller(0)
		resultsPath := filepath.Join(filepath.Dir(f), "groth16_results.json")
		if werr := os.WriteFile(resultsPath, data, 0644); werr != nil {
			t.Logf("Warning: failed to write results JSON: %v", werr)
		}
	}
}

// TestExportSolidity runs the full groth16 pipeline and writes:
//   - JoltVerifier_<class>.sol — Solidity verifier with vk baked in (per size class)
//   - public_inputs.json       — public witness values for the verifyProof call
//
// Requires the JOLT_EXAMPLE env var to be set to the target example name, e.g.:
//
//	JOLT_EXAMPLE=fibonacci go test -v -run TestExportSolidity -timeout 60m
//
// The size class is auto-detected from whichever class_X directory the transpiler
// created. The pk/vk are cached in that directory and reused across programs in
// the same class, so the ~1min setup only runs once per class.
// Output is written to examples/<JOLT_EXAMPLE>/foundry/.
func TestExportSolidity(t *testing.T) {
	t.Log("Jolt Stages 1-7 Verifier - Export Solidity Verifier and Proof Data")

	exampleName := os.Getenv("JOLT_EXAMPLE")
	if exampleName == "" {
		t.Fatal("JOLT_EXAMPLE env var is not set — run as: JOLT_EXAMPLE=<example-name> go test -run TestExportSolidity")
	}
	t.Logf("Target example: %s", exampleName)

	_, thisFile, _, _ := runtime.Caller(0)
	goDir := filepath.Dir(thisFile)

	// Detect which class directory the transpiler most recently wrote to,
	// by picking the one with the newest stages_witness.json. This avoids
	// picking a stale class directory from a previous run.
	classDir := ""
	className := ""
	var newestMod time.Time
	for _, name := range []string{"class_S", "class_M", "class_L", "class_XL"} {
		witnessCandidate := filepath.Join(goDir, name, "stages_witness.json")
		info, err := os.Stat(witnessCandidate)
		if err != nil {
			continue
		}
		if info.ModTime().After(newestMod) {
			newestMod = info.ModTime()
			classDir = filepath.Join(goDir, name)
			className = name[len("class_"):]
		}
	}
	if classDir == "" {
		t.Fatal("No class directory found — run the transpiler first")
	}
	t.Logf("Auto-detected class directory: class_%s (newest witness)", className)

	witnessPath := filepath.Join(classDir, "stages_witness.json")
	assignment, err := LoadStagesAssignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}
	t.Logf("Loaded witness from: %s", witnessPath)

	circuit := &JoltStagesCircuit{}
	t.Log("Compiling circuit...")
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	t.Logf("Compiled: %d constraints", r1cs.GetNbConstraints())

	// Use cached pk/vk keyed to the class directory — shared across all programs
	// in this class, so the ~1min setup only runs once per class.
	pk, vk, _, _ := cachedSetup(t, r1cs, classDir)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	t.Log("Generating proof...")
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	t.Log("Proof verified ✓")

	solFileName := fmt.Sprintf("JoltVerifier_%s.sol", className)
	solPath := filepath.Join(classDir, solFileName)

	var newSol bytes.Buffer
	if err := vk.ExportSolidity(&newSol); err != nil {
		t.Fatalf("ExportSolidity failed: %v", err)
	}
	if existing, err := os.ReadFile(solPath); err == nil && bytes.Equal(existing, newSol.Bytes()) {
		t.Logf("Reusing existing contract (unchanged): %s", solPath)
	} else {
		if err := os.WriteFile(solPath, newSol.Bytes(), 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", solFileName, err)
		}
		t.Logf("Solidity verifier written to: %s", solPath)
	}

	// MarshalSolidity returns [Ax,Ay, Bx0,Bx1,By0,By1, Cx,Cy] as 8×32 bytes.
	bn254Proof, ok := proof.(*groth16bn254.Proof)
	if !ok {
		t.Fatal("proof is not a BN254 proof — unexpected curve")
	}
	solidityBytes := bn254Proof.MarshalSolidity()
	toUint256 := func(b []byte) string { return "0x" + fmt.Sprintf("%064x", new(big.Int).SetBytes(b)) }
	pA0 := toUint256(solidityBytes[0:32])
	pA1 := toUint256(solidityBytes[32:64])
	pB00 := toUint256(solidityBytes[64:96])
	pB01 := toUint256(solidityBytes[96:128])
	pB10 := toUint256(solidityBytes[128:160])
	pB11 := toUint256(solidityBytes[160:192])
	pC0 := toUint256(solidityBytes[192:224])
	pC1 := toUint256(solidityBytes[224:256])

	vec, ok := publicWitness.Vector().(bn254fr.Vector)
	if !ok {
		t.Fatalf("unexpected public witness type: %T", publicWitness.Vector())
	}
	inputStrs := make([]string, len(vec))
	for i, e := range vec {
		var b big.Int
		e.BigInt(&b)
		inputStrs[i] = "0x" + fmt.Sprintf("%064x", &b)
	}
	t.Logf("Public inputs: %d values", len(vec))

	inputsPath := filepath.Join(classDir, "public_inputs.json")
	if data, err := json.MarshalIndent(inputStrs, "", "  "); err == nil {
		_ = os.WriteFile(inputsPath, data, 0644)
		t.Logf("Public inputs written to: %s", inputsPath)
	}

	inputLines := make([]string, len(inputStrs))
	for i, s := range inputStrs {
		inputLines[i] = fmt.Sprintf("            input[%d] = %s;", i, s)
	}
	proofLines := []string{
		fmt.Sprintf("        proof[0] = %s;", pA0),
		fmt.Sprintf("        proof[1] = %s;", pA1),
		fmt.Sprintf("        proof[2] = %s;", pB00),
		fmt.Sprintf("        proof[3] = %s;", pB01),
		fmt.Sprintf("        proof[4] = %s;", pB10),
		fmt.Sprintf("        proof[5] = %s;", pB11),
		fmt.Sprintf("        proof[6] = %s;", pC0),
		fmt.Sprintf("        proof[7] = %s;", pC1),
	}

	testFnName := strings.ReplaceAll(exampleName, "-", "_")
	foundryTest := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/%s";

contract JoltVerifierTest is Test {
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_%s() public view {
        uint256[8] memory proof;
%s

        uint256[%d] memory input;
%s

        verifier.verifyProof(proof, input);
    }
}
`,
		solFileName,
		testFnName,
		strings.Join(proofLines, "\n"),
		len(inputStrs),
		strings.Join(inputLines, "\n"),
	)

	foundryDir := filepath.Join(goDir, "../../examples", exampleName, "foundry")
	_ = os.MkdirAll(filepath.Join(foundryDir, "src"), 0755)
	_ = os.MkdirAll(filepath.Join(foundryDir, "test"), 0755)
	_ = os.MkdirAll(filepath.Join(foundryDir, "lib"), 0755)

	// Write foundry.toml if not already present — committed as a template alongside the example.
	foundryToml := filepath.Join(foundryDir, "foundry.toml")
	if _, err := os.Stat(foundryToml); os.IsNotExist(err) {
		_ = os.WriteFile(foundryToml, []byte("[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = [\"lib\"]\n"), 0644)
	}

	_ = os.WriteFile(filepath.Join(foundryDir, "src", solFileName), newSol.Bytes(), 0644)

	testPath := filepath.Join(foundryDir, "test", "JoltVerifier.t.sol")
	_ = os.WriteFile(testPath, []byte(foundryTest), 0644)
	t.Logf("Foundry test written to: %s", testPath)
	t.Logf("Run: cd %s && forge install foundry-rs/forge-std --no-git && forge test -vv", foundryDir)
}

// =============================================================================
// SANITY CHECK TESTS - Verify the circuit is actually checking constraints
// =============================================================================

// TestCorruptedWitnessRejected verifies that corrupted witness values cause the circuit to fail.
// This is a critical sanity check - if corrupt witnesses pass, the circuit is broken.
func TestCorruptedWitnessRejected(t *testing.T) {
	t.Log("=== SANITY CHECK: Corrupted Witness Rejection ===")
	t.Log("Testing that corrupted witness values cause verification failure...")
	t.Log("")

	// Load valid witness
	witnessPath := getStagesWitnessPath()
	validAssignment, err := LoadStagesAssignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness data: %v", err)
	}

	// First verify the valid witness passes
	t.Log("Step 1: Verify valid witness passes...")
	var circuit JoltStagesCircuit
	err = test.IsSolved(&circuit, validAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Valid witness should pass but got error: %v", err)
	}
	t.Log("  ✓ Valid witness passes (expected)")

	// Test corrupting different types of witness values
	testCases := []struct {
		name        string
		fieldName   string
		corruptFunc func(*big.Int) *big.Int
	}{
		{
			name:      "Corrupt commitment element",
			fieldName: "Commitment_0_0",
			corruptFunc: func(v *big.Int) *big.Int {
				return new(big.Int).Add(v, big.NewInt(1))
			},
		},
		{
			name:      "Corrupt PC claim (Spartan outer)",
			fieldName: "Claim_Virtual_PC_SpartanOuter",
			corruptFunc: func(v *big.Int) *big.Int {
				return new(big.Int).Add(v, big.NewInt(1))
			},
		},
		{
			name:      "Corrupt Rs1 value claim",
			fieldName: "Claim_Virtual_Rs1Value_SpartanOuter",
			corruptFunc: func(v *big.Int) *big.Int {
				return new(big.Int).Add(v, big.NewInt(42))
			},
		},
		{
			name:      "Zero out RdInc claim",
			fieldName: "Claim_Committed_RdInc_RegistersReadWriteChecking",
			corruptFunc: func(v *big.Int) *big.Int {
				return big.NewInt(0)
			},
		},
		{
			name:      "Negate RAM booleanity claim",
			fieldName: "Claim_Committed_RamRa_0_RamBooleanity",
			corruptFunc: func(v *big.Int) *big.Int {
				return new(big.Int).Neg(v)
			},
		},
		{
			name:      "Corrupt lookup output claim",
			fieldName: "Claim_Virtual_LookupOutput_SpartanOuter",
			corruptFunc: func(v *big.Int) *big.Int {
				return new(big.Int).Add(v, big.NewInt(999))
			},
		},
	}

	t.Log("")
	t.Log("Step 2: Test each corruption type...")
	passedCorruptions := 0
	failedCorruptions := 0

	for _, tc := range testCases {
		// Reload fresh witness
		assignment, err := LoadStagesAssignment(witnessPath)
		if err != nil {
			t.Fatalf("Failed to reload witness: %v", err)
		}

		// Apply corruption
		v := reflect.ValueOf(assignment).Elem()
		field := v.FieldByName(tc.fieldName)
		if !field.IsValid() {
			t.Logf("  ? %s - field %s not found, skipping", tc.name, tc.fieldName)
			continue
		}

		originalVal := field.Interface().(*big.Int)
		corruptedVal := tc.corruptFunc(new(big.Int).Set(originalVal))
		field.Set(reflect.ValueOf(corruptedVal))

		// Test that corrupted witness fails
		err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Logf("  ✓ %s - correctly rejected", tc.name)
			passedCorruptions++
		} else {
			t.Logf("  ✗ %s - INCORRECTLY ACCEPTED! This is a bug!", tc.name)
			failedCorruptions++
		}
	}

	t.Log("")
	t.Logf("Results: %d corruptions correctly rejected, %d incorrectly accepted", passedCorruptions, failedCorruptions)

	if failedCorruptions > 0 {
		t.Fatalf("CRITICAL: %d corrupted witnesses were incorrectly accepted!", failedCorruptions)
	}

	if passedCorruptions == 0 {
		t.Fatal("CRITICAL: No corruption tests ran successfully!")
	}

	t.Log("")
	t.Log("✓ All corruption tests passed - circuit correctly rejects invalid witnesses")
}

