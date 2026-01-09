package jolt_verifier

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestCountConstraints(t *testing.T) {
	var circuit Stage1Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("R1CS Constraints: %d\n", cs.GetNbConstraints())
	fmt.Printf("Public inputs: %d\n", cs.GetNbPublicVariables())
	fmt.Printf("Secret inputs: %d\n", cs.GetNbSecretVariables())
}
