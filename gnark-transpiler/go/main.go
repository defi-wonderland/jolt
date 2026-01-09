package jolt_verifier

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func CountConstraints() {
	fmt.Println("Compiling Stage1Circuit to R1CS...")

	// Create circuit instance
	var circuit Stage1Circuit

	// Compile to R1CS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Error compiling circuit: %v\n", err)
		return
	}

	fmt.Println("\n=== Circuit Statistics ===")
	fmt.Printf("Number of constraints: %d\n", cs.GetNbConstraints())
	fmt.Printf("Number of public inputs: %d\n", cs.GetNbPublicVariables())
	fmt.Printf("Number of secret inputs: %d\n", cs.GetNbSecretVariables())
	fmt.Printf("Number of internal variables: %d\n", cs.GetNbInternalVariables())

	// Estimate proving key size
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("Error in setup: %v\n", err)
		return
	}

	fmt.Println("\n=== Groth16 Setup Complete ===")
	fmt.Printf("Proving key generated\n")
	fmt.Printf("Verification key generated\n")

	// Print some info about pk/vk to avoid unused variable warnings
	_ = pk
	_ = vk
}
