package hyrax

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	fr_grumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_grumpkin"
)

// TestConstraintCount measures constraint counts for various MSM sizes.
// This is the key benchmark for validating Hyrax feasibility.
func TestConstraintCount(t *testing.T) {
	// Test multiple sqrt(N) sizes
	// 1024 is the target for N = 2^20 (1M coefficients)
	sizes := []int{4, 16, 64, 256, 1024}

	for _, sqrtN := range sizes {
		t.Run(fmt.Sprintf("sqrtN=%d", sqrtN), func(t *testing.T) {
			// Create circuit with placeholder arrays of the right size
			circuit := createPlaceholderCircuit(sqrtN)

			// Compile to R1CS to count constraints
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				t.Fatalf("Failed to compile circuit: %v", err)
			}

			nbConstraints := cs.GetNbConstraints()
			nbPublicWires := cs.GetNbPublicVariables()
			nbSecretWires := cs.GetNbSecretVariables()

			t.Logf("sqrt(N) = %d (N = %d)", sqrtN, sqrtN*sqrtN)
			t.Logf("  Constraints: %d", nbConstraints)
			t.Logf("  Public wires: %d", nbPublicWires)
			t.Logf("  Secret wires: %d", nbSecretWires)
			t.Logf("  Constraints per scalar mul: ~%d", nbConstraints/(2*sqrtN))
		})
	}
}

// TestSingleScalarMul measures constraints for a single scalar multiplication.
// This isolates the cost of one Grumpkin scalar mul.
func TestSingleScalarMul(t *testing.T) {
	circuit := &SingleScalarMulCircuit{}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	t.Logf("Single Grumpkin scalar mul:")
	t.Logf("  Constraints: %d", cs.GetNbConstraints())
	t.Logf("  Public wires: %d", cs.GetNbPublicVariables())
}

// SingleScalarMulCircuit tests a single scalar multiplication.
type SingleScalarMulCircuit struct {
	Point  sw_grumpkin.G1Affine `gnark:",public"`
	Scalar sw_grumpkin.Scalar   `gnark:",public"`
	Result sw_grumpkin.G1Affine `gnark:",public"`
}

func (c *SingleScalarMulCircuit) Define(api frontend.API) error {
	curve, err := sw_grumpkin.NewCurve(api)
	if err != nil {
		return err
	}

	result := curve.ScalarMul(&c.Point, &c.Scalar)
	curve.AssertIsEqual(result, &c.Result)

	return nil
}

// TestPointAddition measures constraints for a single point addition.
func TestPointAddition(t *testing.T) {
	circuit := &PointAddCircuit{}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	t.Logf("Single Grumpkin point addition:")
	t.Logf("  Constraints: %d", cs.GetNbConstraints())
}

// PointAddCircuit tests a single point addition.
type PointAddCircuit struct {
	P      sw_grumpkin.G1Affine `gnark:",public"`
	Q      sw_grumpkin.G1Affine `gnark:",public"`
	Result sw_grumpkin.G1Affine `gnark:",public"`
}

func (c *PointAddCircuit) Define(api frontend.API) error {
	curve, err := sw_grumpkin.NewCurve(api)
	if err != nil {
		return err
	}

	result := curve.Add(&c.P, &c.Q)
	curve.AssertIsEqual(result, &c.Result)

	return nil
}

// TestFullProveVerify runs a complete prove/verify cycle with small parameters.
// This validates that the circuit is correctly constructed.
func TestFullProveVerify(t *testing.T) {
	sqrtN := 4 // Small size for testing

	// Generate random test data
	rowCommitments, generators, L, U, R, V := generateTestData(sqrtN)

	// Create circuit
	circuit := createPlaceholderCircuit(sqrtN)

	// Create witness
	witness := &HyraxVerifierCircuit{
		SqrtN:          sqrtN,
		RowCommitments: rowCommitments,
		Generators:     generators,
		L:              L,
		U:              U,
		R:              R,
		V:              V,
	}

	// Compile
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Setup
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Prove
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		t.Fatalf("Failed to prove: %v", err)
	}

	// Verify
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	t.Logf("Full prove/verify cycle succeeded for sqrt(N) = %d", sqrtN)
}

// TestMSMRelationship verifies that our test data satisfies the critical Hyrax constraint:
// Com(u) == C' where C' = Σ L[a] · C[a] and Com(u) = Σ u[j] · G[j]
//
// This is the binding property that makes Hyrax secure.
func TestMSMRelationship(t *testing.T) {
	sqrtN := 4

	// Extract concrete L values
	lValues := make([]*big.Int, sqrtN)
	for a := 0; a < sqrtN; a++ {
		lValues[a] = big.NewInt(int64(a + 1)) // L[a] = a + 1 (from generateTestData)
	}

	// Extract concrete U values (computed as u[j] = Σ_a L[a] · F[a][j])
	uValues := make([]*big.Int, sqrtN)
	for j := 0; j < sqrtN; j++ {
		var sum int64 = 0
		for a := 0; a < sqrtN; a++ {
			F_aj := int64((a + 1) * (j + 1)) // F[a][j] = (a+1)*(j+1)
			sum += int64(a+1) * F_aj         // L[a] * F[a][j]
		}
		uValues[j] = big.NewInt(sum)
	}

	// Recompute generators
	generatorsConcrete := make([]grumpkin.G1Affine, sqrtN)
	_, gen := grumpkin.Generators()
	for j := 0; j < sqrtN; j++ {
		var scalar big.Int
		scalar.SetInt64(int64(j + 1))
		generatorsConcrete[j].ScalarMultiplication(&gen, &scalar)
	}

	// Recompute row commitments
	F := make([][]int64, sqrtN)
	for a := 0; a < sqrtN; a++ {
		F[a] = make([]int64, sqrtN)
		for b := 0; b < sqrtN; b++ {
			F[a][b] = int64((a + 1) * (b + 1))
		}
	}

	rowCommitmentsConcrete := make([]grumpkin.G1Affine, sqrtN)
	for a := 0; a < sqrtN; a++ {
		var sum grumpkin.G1Affine
		for j := 0; j < sqrtN; j++ {
			var scalar big.Int
			scalar.SetInt64(F[a][j])
			var term grumpkin.G1Affine
			term.ScalarMultiplication(&generatorsConcrete[j], &scalar)
			sum.Add(&sum, &term)
		}
		rowCommitmentsConcrete[a] = sum
	}

	// Compute C' = Σ L[a] · C[a]
	var Cprime grumpkin.G1Affine
	for a := 0; a < sqrtN; a++ {
		var term grumpkin.G1Affine
		term.ScalarMultiplication(&rowCommitmentsConcrete[a], lValues[a])
		Cprime.Add(&Cprime, &term)
	}

	// Compute Com(u) = Σ u[j] · G[j]
	var ComU grumpkin.G1Affine
	for j := 0; j < sqrtN; j++ {
		var term grumpkin.G1Affine
		term.ScalarMultiplication(&generatorsConcrete[j], uValues[j])
		ComU.Add(&ComU, &term)
	}

	// Check equality
	if !Cprime.Equal(&ComU) {
		t.Fatalf("MSM relationship violated: Com(u) != C'\nCprime: %v\nComU: %v", Cprime, ComU)
	}

	t.Logf("MSM relationship verified: Com(u) == C'")
	t.Logf("  C' = %s", Cprime.String())
	t.Logf("  Com(u) = %s", ComU.String())

	// Also verify the dot product
	var dotProduct int64 = 0
	for j := 0; j < sqrtN; j++ {
		dotProduct += uValues[j].Int64() * int64(j+1) // u[j] * R[j] where R[j] = j+1
	}
	t.Logf("  <u, R> = %d", dotProduct)
}

// TestRejectsInvalidProof verifies that the circuit rejects an invalid witness.
// This is a soundness test - we create data where Com(u) != C'.
func TestRejectsInvalidProof(t *testing.T) {
	sqrtN := 4

	// Get valid test data
	rowCommitments, generators, L, U, R, _ := generateTestData(sqrtN)

	// Corrupt one of the U values (this will make Com(u) != C')
	var corruptedU []sw_grumpkin.Scalar
	corruptedU = append(corruptedU, U...)
	var badScalar fr_grumpkin.Element
	badScalar.SetInt64(99999) // Different from the correct value
	corruptedU[0] = sw_grumpkin.NewScalar(badScalar)

	// Also need to update V to match the corrupted U for the dot product
	// (otherwise the circuit might fail on the dot product check instead)
	var newV int64 = 99999 * 1 // corruptedU[0] * R[0]
	for j := 1; j < sqrtN; j++ {
		// Original u[j] = Σ_a L[a] * F[a][j]
		var sum int64 = 0
		for a := 0; a < sqrtN; a++ {
			F_aj := int64((a + 1) * (j + 1))
			sum += int64(a+1) * F_aj
		}
		newV += sum * int64(j+1)
	}

	// Create circuit
	circuit := createPlaceholderCircuit(sqrtN)

	// Create invalid witness
	witness := &HyraxVerifierCircuit{
		SqrtN:          sqrtN,
		RowCommitments: rowCommitments,
		Generators:     generators,
		L:              L,
		U:              corruptedU,
		R:              R,
		V:              frontend.Variable(newV),
	}

	// Compile
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Setup
	pk, _, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Prove - this should fail because Com(u) != C'
	_, err = groth16.Prove(cs, pk, fullWitness)
	if err == nil {
		t.Fatalf("Expected proof to fail with invalid witness, but it succeeded!")
	}

	t.Logf("Circuit correctly rejected invalid proof: %v", err)
}

// createPlaceholderCircuit creates a circuit with the right array sizes for compilation.
func createPlaceholderCircuit(sqrtN int) *HyraxVerifierCircuit {
	return &HyraxVerifierCircuit{
		SqrtN:          sqrtN,
		RowCommitments: make([]sw_grumpkin.G1Affine, sqrtN),
		Generators:     make([]sw_grumpkin.G1Affine, sqrtN),
		L:              make([]sw_grumpkin.Scalar, sqrtN),
		U:              make([]sw_grumpkin.Scalar, sqrtN),
		R:              make([]frontend.Variable, sqrtN),
		V:              0,
	}
}

// generateTestData creates valid Hyrax test vectors that satisfy the protocol constraints.
//
// For valid Hyrax verification, we need:
//   1. C' = Σ L[a] · RowCommitments[a]     (MSM #1 - verifier computes)
//   2. Com(u) = Σ u[j] · Generators[j]    (MSM #2 - verifier computes)
//   3. Com(u) == C'                         (Check 1 - binding)
//   4. <u, R> == v                          (Check 2 - evaluation)
//
// To satisfy Check 1 (Com(u) == C'), we construct row commitments such that
// when weighted by L, they produce the same point as u weighted by generators.
//
// Strategy: Use a simple coefficient matrix F where we can compute everything.
func generateTestData(sqrtN int) (
	rowCommitments []sw_grumpkin.G1Affine,
	generators []sw_grumpkin.G1Affine,
	L []sw_grumpkin.Scalar,
	U []sw_grumpkin.Scalar,
	R []frontend.Variable,
	V frontend.Variable,
) {
	// Get the Grumpkin generator point
	_, g1Gen := grumpkin.Generators()

	// Generate deterministic SRS generators: G[j] = (j+1) · G
	generators = make([]sw_grumpkin.G1Affine, sqrtN)
	generatorsConcrete := make([]grumpkin.G1Affine, sqrtN)
	for j := 0; j < sqrtN; j++ {
		var scalar big.Int
		scalar.SetInt64(int64(j + 1))
		generatorsConcrete[j].ScalarMultiplication(&g1Gen, &scalar)
		generators[j] = sw_grumpkin.NewG1Affine(generatorsConcrete[j])
	}

	// Create a simple coefficient matrix F (sqrtN x sqrtN)
	// F[a][b] = (a+1) * (b+1) for simplicity
	F := make([][]int64, sqrtN)
	for a := 0; a < sqrtN; a++ {
		F[a] = make([]int64, sqrtN)
		for b := 0; b < sqrtN; b++ {
			F[a][b] = int64((a + 1) * (b + 1))
		}
	}

	// Compute row commitments: C[a] = Σ_j F[a][j] · G[j]
	rowCommitments = make([]sw_grumpkin.G1Affine, sqrtN)
	rowCommitmentsConcrete := make([]grumpkin.G1Affine, sqrtN)
	for a := 0; a < sqrtN; a++ {
		// C[a] = Σ_j F[a][j] · G[j]
		var sum grumpkin.G1Affine
		sum.Set(&grumpkin.G1Affine{}) // identity (point at infinity)
		for j := 0; j < sqrtN; j++ {
			var scalar big.Int
			scalar.SetInt64(F[a][j])
			var term grumpkin.G1Affine
			term.ScalarMultiplication(&generatorsConcrete[j], &scalar)
			sum.Add(&sum, &term)
		}
		rowCommitmentsConcrete[a] = sum
		rowCommitments[a] = sw_grumpkin.NewG1Affine(rowCommitmentsConcrete[a])
	}

	// Generate L (eq vector) - simple values for testing
	// L[a] = a + 1
	L = make([]sw_grumpkin.Scalar, sqrtN)
	lValues := make([]int64, sqrtN)
	for a := 0; a < sqrtN; a++ {
		lValues[a] = int64(a + 1)
		var lElem fr_grumpkin.Element
		lElem.SetInt64(lValues[a])
		L[a] = sw_grumpkin.NewScalar(lElem)
	}

	// Compute u = L^T · F (the projection vector)
	// u[j] = Σ_a L[a] · F[a][j]
	U = make([]sw_grumpkin.Scalar, sqrtN)
	uValues := make([]int64, sqrtN)
	for j := 0; j < sqrtN; j++ {
		var sum int64 = 0
		for a := 0; a < sqrtN; a++ {
			sum += lValues[a] * F[a][j]
		}
		uValues[j] = sum
		var uElem fr_grumpkin.Element
		uElem.SetInt64(uValues[j])
		U[j] = sw_grumpkin.NewScalar(uElem)
	}

	// Generate R (eq vector) - simple values for testing
	// R[b] = b + 1
	R = make([]frontend.Variable, sqrtN)
	rValues := make([]int64, sqrtN)
	for b := 0; b < sqrtN; b++ {
		rValues[b] = int64(b + 1)
		R[b] = frontend.Variable(rValues[b])
	}

	// Compute v = <u, R> = Σ_j u[j] · R[j]
	var vValue int64 = 0
	for j := 0; j < sqrtN; j++ {
		vValue += uValues[j] * rValues[j]
	}
	V = frontend.Variable(vValue)

	// Verification: Com(u) should equal C' = Σ L[a] · C[a]
	// This is guaranteed by construction because:
	//   C' = Σ_a L[a] · (Σ_j F[a][j] · G[j])
	//      = Σ_j (Σ_a L[a] · F[a][j]) · G[j]
	//      = Σ_j u[j] · G[j]
	//      = Com(u)

	return
}
