package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	jolt "jolt_verifier"
)

func main() {
	fmt.Println("Compiling Stage1Circuit to R1CS...")

	// Create circuit instance
	var circuit jolt.Stage1Circuit

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
}
