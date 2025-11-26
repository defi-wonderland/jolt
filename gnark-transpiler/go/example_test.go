package jolt_verifier

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ExampleCircuit is a simple test circuit
// In production, this would be the generated Stage1Circuit
type ExampleCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
}

func (circuit *ExampleCircuit) Define(api frontend.API) error {
	// Z = X + Y
	result := api.Add(circuit.X, circuit.Y)
	api.AssertIsEqual(result, circuit.Z)
	return nil
}

func TestExampleCircuit(t *testing.T) {
	// 1. Define circuit
	var circuit ExampleCircuit

	// 2. Compile to R1CS
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Setup (trusted setup)
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create witness (assignment)
	assignment := &ExampleCircuit{
		X: big.NewInt(3),
		Y: big.NewInt(5),
		Z: big.NewInt(8), // 3 + 5 = 8
	}

	// 5. Create full witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	// 6. Generate proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}

	// 7. Create public witness
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}

	// 8. Verify proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatal("verification failed:", err)
	}

	t.Log("Proof verified successfully!")
}

func TestWitnessLoading(t *testing.T) {
	// Test JSON parsing
	jsonData := `{
		"tau": ["123", "456"],
		"r0": "789",
		"sumcheck_challenges": ["111"],
		"uni_skip_poly_coeffs": ["222", "333"],
		"sumcheck_round_polys": [["444"]],
		"expected_final_claim": "555"
	}`

	var witness Stage1WitnessJSON
	if err := json.Unmarshal([]byte(jsonData), &witness); err != nil {
		t.Fatal(err)
	}

	if len(witness.Tau) != 2 {
		t.Errorf("expected 2 tau values, got %d", len(witness.Tau))
	}

	if witness.R0 != "789" {
		t.Errorf("expected r0=789, got %s", witness.R0)
	}

	// Test flat conversion
	values, err := witness.ToFlatValues()
	if err != nil {
		t.Fatal(err)
	}

	// Expected: 123, 456, 789, 111, 222, 333, 444, 555
	expected := []int64{123, 456, 789, 111, 222, 333, 444, 555}
	if len(values) != len(expected) {
		t.Errorf("expected %d values, got %d", len(expected), len(values))
	}

	for i, v := range values {
		if v.Int64() != expected[i] {
			t.Errorf("value[%d]: expected %d, got %d", i, expected[i], v.Int64())
		}
	}

	t.Log("Witness loading works correctly!")
}

// TestStage1Circuit tests the transpiled Stage1 verifier circuit
func TestStage1Circuit(t *testing.T) {
	// 1. Define circuit
	var circuit Stage1Circuit

	// 2. Compile to R1CS
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Circuit compiled: %d constraints", r1cs.GetNbConstraints())

	// 3. Setup (trusted setup)
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create witness with valid values
	// Variable mapping from main.rs:
	// X_0, X_1: tau challenges (not used in constraints)
	// X_2, X_3: sumcheck challenges
	// X_4: r0 challenge
	// X_5, X_6, X_7: uni_skip_poly_coeffs
	// X_8, X_9: round 0 polynomial coefficients
	// X_10, X_11: round 1 polynomial coefficients
	//
	// Constraints:
	// - powerSumCheck = X_5*10 + X_6*5 + X_7*85 == 0
	// - consistencyCheck0 = 2*X_8 + X_9 - (X_5 + X_6*X_4 + X_7*X_4^2) == 0
	// - consistencyCheck1 = 2*X_10 + X_11 - (X_8 + X_9*X_2) == 0
	// - finalClaim = X_10 + X_11*X_3 == ExpectedFinalClaim
	//
	// Simple solution: all zeros
	// X_5=0, X_6=0, X_7=0 => powerSumCheck = 0 ✓
	// X_8=0, X_9=0 => consistencyCheck0 = 0 - 0 = 0 ✓
	// X_10=0, X_11=0 => consistencyCheck1 = 0 - 0 = 0 ✓
	// finalClaim = 0 + 0 = 0, ExpectedFinalClaim = 0 ✓

	assignment := &Stage1Circuit{
		X_2:                big.NewInt(0),
		X_3:                big.NewInt(0),
		X_4:                big.NewInt(0),
		X_5:                big.NewInt(0),
		X_6:                big.NewInt(0),
		X_7:                big.NewInt(0),
		X_8:                big.NewInt(0),
		X_9:                big.NewInt(0),
		X_10:               big.NewInt(0),
		X_11:               big.NewInt(0),
		ExpectedFinalClaim: big.NewInt(0),
	}

	// 5. Create full witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	// 6. Generate proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}

	// 7. Create public witness
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}

	// 8. Verify proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatal("verification failed:", err)
	}

	t.Log("Stage1Circuit proof verified successfully!")
}
