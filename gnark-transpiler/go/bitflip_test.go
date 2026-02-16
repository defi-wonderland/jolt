//go:build debug_intermediates

package jolt_verifier

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// captureStdout runs fn() and returns everything written to os.Stdout.
// Reads in a separate goroutine to avoid pipe buffer deadlock.
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()

	fn()

	w.Close()
	os.Stdout = old
	return <-done
}

// parseAssertionValues extracts assertion_N_lhs / assertion_N_rhs values from api.Println output.
func parseAssertionValues(output string) map[string]string {
	vals := make(map[string]string)
	re := regexp.MustCompile(`(assertion_\d+_(?:lhs|rhs))[:\s]+(\d+)`)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		vals[match[1]] = match[2]
	}
	return vals
}

// solveAndCapture loads witness, optionally corrupts one field, runs the solver,
// and returns the captured assertion values + whether the solver succeeded.
func solveAndCapture(t *testing.T, corruptField string, flipBit int) (map[string]string, bool) {
	t.Helper()

	witnessPath := getStages16WitnessPath()
	assignment, err := LoadStages16Assignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}

	if corruptField != "" {
		v := reflect.ValueOf(assignment).Elem()
		field := v.FieldByName(corruptField)
		if !field.IsValid() || field.IsNil() {
			t.Fatalf("Field %s not found or nil", corruptField)
		}
		original := field.Interface().(*big.Int)
		corrupted := new(big.Int).Set(original)
		corrupted.Xor(corrupted, new(big.Int).Lsh(big.NewInt(1), uint(flipBit)))
		field.Set(reflect.ValueOf(corrupted))
	}

	var circuit JoltStages16Circuit
	var solveErr error

	stdout := captureStdout(func() {
		solveErr = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	})

	vals := parseAssertionValues(stdout)
	return vals, solveErr == nil
}

func TestBitFlipAvalanche(t *testing.T) {
	t.Log("=== Bit Flip Avalanche Test ===")
	t.Log("Which assertion values change when we flip 1 bit in different witness fields?")
	t.Log("")

	// Step 1: baseline with correct witness
	t.Log("Running solver with CORRECT witness...")
	correctVals, correctOk := solveAndCapture(t, "", 0)
	if !correctOk {
		t.Fatal("Correct witness should pass but solver failed")
	}
	t.Logf("  Captured %d assertion values (expected 30: 15 lhs + 15 rhs)", len(correctVals))
	if len(correctVals) < 30 {
		t.Fatalf("Expected 30 assertion values, got %d", len(correctVals))
	}

	t.Log("")
	t.Log("Correct assertion LHS values:")
	for i := 0; i < 15; i++ {
		lhs := correctVals[fmt.Sprintf("assertion_%d_lhs", i)]
		t.Logf("  a%-2d = %s...", i, truncVal(lhs, 40))
	}

	// Step 2: test multiple witness fields
	fields := []struct {
		name string
		bit  int
		desc string
	}{
		{"Commitment_0_0", 7, "commitment (Poseidon transcript)"},
		{"Stage1_Sumcheck_R0_0", 3, "stage1 sumcheck round coeff"},
		{"Stage1_Uni_Skip_Coeff_0", 11, "uni_skip polynomial coeff"},
		{"Claim_Polynomial_Virtual_Rs1Value_RegistersClaimReduction", 5, "Rs1 claim (feeds a5/a7)"},
		{"Claim_Polynomial_Virtual_LookupOutput_InstructionClaimReduction", 9, "lookup output claim (feeds a10/a11)"},
	}

	for _, f := range fields {
		t.Log("")
		t.Logf("--- Flip bit %d of %s (%s) ---", f.bit, f.name, f.desc)

		corruptVals, corruptOk := solveAndCapture(t, f.name, f.bit)
		if corruptOk {
			t.Logf("  WARN: solver PASSED with corrupted witness!")
		} else {
			t.Logf("  Solver correctly REJECTED")
		}

		changed := 0
		var list []int
		for i := 0; i < 15; i++ {
			key := fmt.Sprintf("assertion_%d_lhs", i)
			if correctVals[key] != "" && corruptVals[key] != "" && correctVals[key] != corruptVals[key] {
				changed++
				list = append(list, i)
			}
		}
		t.Logf("  Changed: %d/15 — assertions %v", changed, list)
	}
}

func truncVal(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// TestRustGoAssertionMatch loads the 15 assertion values exported by Rust
// (rust_all_assertions.json) and compares them 1:1 against the Go circuit's
// assertion values captured via api.Println in debug mode.
func TestRustGoAssertionMatch(t *testing.T) {
	t.Log("=== Rust vs Go: All 15 Assertions ===")
	t.Log("")

	// Load Rust assertions from JSON
	_, currentFile, _, _ := runtime.Caller(0)
	rustPath := filepath.Join(filepath.Dir(currentFile), "rust_all_assertions.json")

	rustData, err := os.ReadFile(rustPath)
	if err != nil {
		t.Fatalf("Failed to read %s\nRun: cargo run -p gnark-transpiler --bin verify_real --features debug-expected-output\nError: %v", rustPath, err)
	}

	var rustJSON struct {
		Assertions []struct {
			Index int    `json:"index"`
			Lhs   string `json:"lhs"`
			Rhs   string `json:"rhs"`
		} `json:"assertions"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rustData, &rustJSON); err != nil {
		t.Fatalf("Failed to parse Rust JSON: %v", err)
	}
	t.Logf("Loaded %d Rust assertions from %s", rustJSON.Count, rustPath)

	// Run Go solver in debug mode and capture assertion values
	t.Log("Running Go solver to capture assertion values...")
	goVals, goOk := solveAndCapture(t, "", 0)
	if !goOk {
		t.Fatal("Go solver failed with correct witness")
	}
	t.Logf("Captured %d Go assertion values", len(goVals))
	t.Log("")

	// Compare 1:1
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	mismatches := 0

	for _, ra := range rustJSON.Assertions {
		goLhsKey := fmt.Sprintf("assertion_%d_lhs", ra.Index)
		goRhsKey := fmt.Sprintf("assertion_%d_rhs", ra.Index)
		goLhs := goVals[goLhsKey]
		goRhs := goVals[goRhsKey]

		if goLhs == "" || goRhs == "" {
			t.Logf("  [?] a%d: Go value missing (lhs=%q, rhs=%q)", ra.Index, goLhs, goRhs)
			mismatches++
			continue
		}

		// Compare lhs values (mod p)
		rustLhs, _ := new(big.Int).SetString(ra.Lhs, 10)
		rustRhs, _ := new(big.Int).SetString(ra.Rhs, 10)
		gLhs, _ := new(big.Int).SetString(goLhs, 10)
		gRhs, _ := new(big.Int).SetString(goRhs, 10)

		diffLhs := new(big.Int).Sub(rustLhs, gLhs)
		diffLhs.Mod(diffLhs, p)
		diffRhs := new(big.Int).Sub(rustRhs, gRhs)
		diffRhs.Mod(diffRhs, p)

		lhsOk := diffLhs.Sign() == 0
		rhsOk := diffRhs.Sign() == 0

		if lhsOk && rhsOk {
			t.Logf("  [ok] a%d: lhs=%s...  rhs=%s...", ra.Index, truncVal(ra.Lhs, 30), truncVal(ra.Rhs, 30))
		} else {
			t.Logf("  [FAIL] a%d:", ra.Index)
			if !lhsOk {
				t.Logf("    lhs: Rust=%s  Go=%s", ra.Lhs, goLhs)
			}
			if !rhsOk {
				t.Logf("    rhs: Rust=%s  Go=%s", ra.Rhs, goRhs)
			}
			mismatches++
		}
	}

	t.Log("")
	if mismatches > 0 {
		t.Fatalf("FAIL: %d/%d assertion mismatches between Rust and Go", mismatches, rustJSON.Count)
	}
	t.Logf("All %d assertions match between Rust and Go.", rustJSON.Count)
}
