package jolt_verifier

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// getWitnessDataPath returns the path to witness_data.json
func getWitnessDataPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "data", "witness_data.json")
}

func TestStage1Circuit(t *testing.T) {
	// Load witness from JSON file
	witnessPath := getWitnessDataPath()
	assignment, err := LoadStage1Assignment(witnessPath)
	if err != nil {
		t.Fatalf("Failed to load witness data: %v", err)
	}

	var circuit Stage1Circuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	t.Logf("Circuit compiled with %d constraints", r1cs.GetNbConstraints())

	// Setup
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Prove
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Fatalf("Failed to prove: %v", err)
	}

	// Verify
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	t.Log("✓ Stage 1 circuit verification passed!")
}
