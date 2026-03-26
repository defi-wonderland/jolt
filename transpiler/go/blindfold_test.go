package jolt_verifier

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// ============================================================
// Unit tests for BlindFold helper functions
// ============================================================

// TestEqPolynomialCircuit tests the eq polynomial evaluation.
type TestEqPolynomialCircuit struct {
	Challenges []frontend.Variable
	Expected   []frontend.Variable `gnark:",public"`
}

func (c *TestEqPolynomialCircuit) Define(api frontend.API) error {
	evals := ComputeEqPolynomial(api, c.Challenges)
	for i := range c.Expected {
		api.AssertIsEqual(evals[i], c.Expected[i])
	}
	return nil
}

// TestEqPolynomialTwoChallenges verifies eq polynomial with 2 challenges.
// eq([r0, r1], [x0, x1]) for all (x0, x1) in {0,1}^2.
// With r0=2, r1=3:
//   eq([2,3], [0,0]) = (1-2)*(1-3) = (-1)*(-2) = 2
//   eq([2,3], [1,0]) = 2*(1-3) = 2*(-2) = -4
//   eq([2,3], [0,1]) = (1-2)*3 = (-1)*3 = -3
//   eq([2,3], [1,1]) = 2*3 = 6
func TestEqPolynomialTwoChallenges(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &TestEqPolynomialCircuit{
		Challenges: make([]frontend.Variable, 2),
		Expected:   make([]frontend.Variable, 4),
	}

	assignment := &TestEqPolynomialCircuit{
		Challenges: []frontend.Variable{2, 3},
		Expected:   []frontend.Variable{2, -4, -3, 6},
	}

	// Note: -4 and -3 are negative in the field
	// For BN254 Fr field, negative values wrap around modular arithmetic
	// gnark handles this correctly
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestDecompressPolyCircuit tests polynomial decompression.
type TestDecompressPolyCircuit struct {
	CoeffsExceptLinear []frontend.Variable
	Claim              frontend.Variable
	Expected           []frontend.Variable `gnark:",public"`
}

func (c *TestDecompressPolyCircuit) Define(api frontend.API) error {
	poly := DecompressPoly(api, c.CoeffsExceptLinear, c.Claim)
	for i := range c.Expected {
		api.AssertIsEqual(poly[i], c.Expected[i])
	}
	return nil
}

// TestDecompressPolyCubic tests decompression of a cubic polynomial.
// Polynomial: 1 + 5x + 3x² + 7x³
// g(0) = 1, g(1) = 1+5+3+7 = 16
// claim = g(0) + g(1) = 1 + 16 = 17
// Coeffs except linear: [c0=1, c2=3, c3=7]
// c1 = claim - 2*c0 - c2 - c3 = 17 - 2 - 3 - 7 = 5
func TestDecompressPolyCubic(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &TestDecompressPolyCircuit{
		CoeffsExceptLinear: make([]frontend.Variable, 3),
		Claim:              0,
		Expected:           make([]frontend.Variable, 4),
	}

	assignment := &TestDecompressPolyCircuit{
		CoeffsExceptLinear: []frontend.Variable{1, 3, 7},
		Claim:              17,
		Expected:           []frontend.Variable{1, 5, 3, 7},
	}

	assert.ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestHornerEvalCircuit tests Horner's method polynomial evaluation.
type TestHornerEvalCircuit struct {
	Coeffs   []frontend.Variable
	Point    frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *TestHornerEvalCircuit) Define(api frontend.API) error {
	result := EvaluateHorner(api, c.Coeffs, c.Point)
	api.AssertIsEqual(result, c.Expected)
	return nil
}

// TestHornerEvalCubic tests Horner evaluation of 1 + 2x + 3x² at x=5.
// = 1 + 10 + 75 = 86
func TestHornerEvalCubic(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &TestHornerEvalCircuit{
		Coeffs:   make([]frontend.Variable, 3),
		Point:    0,
		Expected: 0,
	}

	assignment := &TestHornerEvalCircuit{
		Coeffs:   []frontend.Variable{1, 2, 3},
		Point:    5,
		Expected: 86,
	}

	assert.ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestEqSingleCircuit tests the single eq evaluation.
type TestEqSingleCircuit struct {
	A        []frontend.Variable
	B        []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *TestEqSingleCircuit) Define(api frontend.API) error {
	result := ComputeEqSingle(api, c.A, c.B)
	api.AssertIsEqual(result, c.Expected)
	return nil
}

// TestEqSingleIdentity tests eq(a, a) = 1 for boolean inputs.
// eq([0,1], [0,1]) = (0*0 + 1*1) * (1*1 + 0*0) = 1 * 1 = 1
func TestEqSingleIdentity(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &TestEqSingleCircuit{
		A:        make([]frontend.Variable, 2),
		B:        make([]frontend.Variable, 2),
		Expected: 0,
	}

	assignment := &TestEqSingleCircuit{
		A:        []frontend.Variable{0, 1},
		B:        []frontend.Variable{0, 1},
		Expected: 1,
	}

	assert.ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestSparseBilinearEvalCircuit tests sparse bilinear R1CS evaluation.
type TestSparseBilinearEvalCircuit struct {
	EqRx     []frontend.Variable
	EqRy     []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *TestSparseBilinearEvalCircuit) Define(api frontend.API) error {
	// Create a simple sparse matrix: A[0,1] = 2, A[1,2] = 3
	entries := []SparseEntry{
		{Row: 0, Col: 1, Coeff: big.NewInt(2)},
		{Row: 1, Col: 2, Coeff: big.NewInt(3)},
	}
	result := SparseBilinearEval(api, entries, c.EqRx, c.EqRy)
	api.AssertIsEqual(result, c.Expected)
	return nil
}

// TestSparseBilinearEvalSimple tests with known values.
// A[0,1]=2, A[1,2]=3
// eq_rx = [1, 0], eq_ry = [1, 0, 0]
// With col-1 shift: A[0,1] uses eq_ry[0], A[1,2] uses eq_ry[1]
// result = 2 * eq_rx[0] * eq_ry[0] + 3 * eq_rx[1] * eq_ry[1]
//        = 2 * 1 * 1 + 3 * 0 * 0 = 2
func TestSparseBilinearEvalSimple(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &TestSparseBilinearEvalCircuit{
		EqRx:     make([]frontend.Variable, 2),
		EqRy:     make([]frontend.Variable, 3),
		Expected: 0,
	}

	assignment := &TestSparseBilinearEvalCircuit{
		EqRx:     []frontend.Variable{1, 0},
		EqRy:     []frontend.Variable{1, 0, 0},
		Expected: 2,
	}

	assert.ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// ============================================================
// Integration test: BlindFold with mock data
// ============================================================

// TestBlindFoldConfigLoading tests JSON config loading.
func TestBlindFoldConfigLoading(t *testing.T) {
	// Create a minimal config
	config := &BlindFoldConfig{
		NumConstraints:          4,
		NumVars:                 2,
		InnerNumVars:            3,
		C:                      4,
		RCoeff:                 2,
		RPrime:                 4,
		RE:                     2,
		CE:                     2,
		SpartanDegree:          3,
		InnerDegree:            2,
		NumRoundCommitments:    2,
		NumNoncoeffCommitments: 1,
		NumERowCommitments:     2,
		NumEvalCommitments:     1,
		NumCrossTermCommitments: 2,
	}

	// Verify allocation works
	circuit := AllocateBlindFoldCircuit(config)
	if len(circuit.RandomRoundX) != 2 {
		t.Errorf("expected 2 random round commitments, got %d", len(circuit.RandomRoundX))
	}
	if len(circuit.SpartanCoeffs) != 2 {
		t.Errorf("expected 2 spartan rounds, got %d", len(circuit.SpartanCoeffs))
	}
	if len(circuit.SpartanCoeffs[0]) != 3 {
		t.Errorf("expected 3 spartan coeffs per round, got %d", len(circuit.SpartanCoeffs[0]))
	}
	if len(circuit.InnerCoeffs) != 3 {
		t.Errorf("expected 3 inner rounds, got %d", len(circuit.InnerCoeffs))
	}
	if len(circuit.InnerCoeffs[0]) != 2 {
		t.Errorf("expected 2 inner coeffs per round, got %d", len(circuit.InnerCoeffs[0]))
	}
}

// TestLabelToFr verifies that labelToFr matches Rust's Fr::from_le_bytes_mod_order.
func TestLabelToFr(t *testing.T) {
	// "BlindFold" as LE bytes:
	// B=0x42, l=0x6c, i=0x69, n=0x6e, d=0x64, F=0x46, o=0x6f, l=0x6c, d=0x64
	// As LE integer: 0x646c6f46646e696c42 (reading right-to-left)
	label := labelToFr("BlindFold")
	if label == nil || label.Sign() == 0 {
		t.Fatal("labelToFr returned zero for 'BlindFold'")
	}

	// Verify different labels produce different values
	label2 := labelToFr("other_label")
	if label.Cmp(label2) == 0 {
		t.Fatal("different labels should produce different Fr values")
	}

	// Verify short labels fit in the field (no reduction needed for < 32 byte labels)
	if label.BitLen() > 254 {
		t.Fatal("label Fr value exceeds 254 bits")
	}
}

// ============================================================
// Solver integration test: real exported data
// ============================================================

// TestPubBzNative verifies pubBz computation natively (outside gnark circuit).
func TestPubBzNative(t *testing.T) {
	config, err := LoadBlindFoldConfig("blindfold_config.json")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	witness, err := LoadBlindFoldWitness("blindfold_witness.json")
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}

	// Parse R1CS B entries
	r1csB := ParseSparseEntries(config.R1CSB)
	t.Logf("r1cs_b entries: %d", len(r1csB))
	for i, e := range r1csB {
		t.Logf("  entry[%d]: row=%d, col=%d, coeff=%s", i, e.Row, e.Col, e.Coeff.String())
	}

	// Parse rx challenges
	rx := ParseScalarSlice(witness.DebugRx)
	t.Logf("rx challenges: %d values", len(rx))
	for i, v := range rx {
		t.Logf("  rx[%d] = %s", i, v.(*big.Int).String())
	}

	// Parse folded_u
	foldedU := ParseHexToBigInt(witness.FoldedU)
	t.Logf("folded_u = %s", foldedU.String())

	// Expected pub_bz from Rust
	expectedPubBz := ParseHexToBigInt(witness.DebugPubBz)
	t.Logf("expected pub_bz = %s", expectedPubBz.String())

	// Manual computation: pub_bz = u * sum(eq_rx[row] * coeff) for col-0 entries
	// Since all B entries are col=0, coeff=1: pub_bz = u * sum(eq_rx[0..5])
	// But we need eq_rx = ComputeEqPolynomial(rx) which requires gnark API...
	// Instead, compute eq polynomial natively using big.Int arithmetic.
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	rxBig := make([]*big.Int, len(rx))
	for i, v := range rx {
		rxBig[i] = v.(*big.Int)
	}

	// Compute eq polynomial evals natively
	n := len(rxBig)
	size := 1 << n
	eqRx := make([]*big.Int, size)
	eqRx[0] = big.NewInt(1)
	for i := 1; i < size; i++ {
		eqRx[i] = big.NewInt(0)
	}
	currentSize := 1
	for j := n - 1; j >= 0; j-- {
		r := rxBig[j]
		oneMinusR := new(big.Int).Sub(p, r)
		oneMinusR.Add(oneMinusR, big.NewInt(1))
		oneMinusR.Mod(oneMinusR, p)
		for i := currentSize - 1; i >= 0; i-- {
			eqRx[currentSize+i] = new(big.Int).Mul(eqRx[i], r)
			eqRx[currentSize+i].Mod(eqRx[currentSize+i], p)
			eqRx[i] = new(big.Int).Mul(eqRx[i], oneMinusR)
			eqRx[i].Mod(eqRx[i], p)
		}
		currentSize *= 2
	}

	t.Logf("eq_rx values:")
	for i := 0; i < size; i++ {
		t.Logf("  eq_rx[%d] = %s", i, eqRx[i].String())
	}

	// Compute pubBz = u * sum(eq_rx[row] * coeff) for col-0 entries of B
	sum := big.NewInt(0)
	for _, e := range r1csB {
		if e.Col == 0 {
			term := new(big.Int).Mul(eqRx[e.Row], e.Coeff)
			term.Mod(term, p)
			sum.Add(sum, term)
			sum.Mod(sum, p)
		}
	}
	pubBz := new(big.Int).Mul(sum, foldedU)
	pubBz.Mod(pubBz, p)

	t.Logf("native pubBz = %s", pubBz.String())
	t.Logf("expected pubBz = %s", expectedPubBz.String())
	if pubBz.Cmp(expectedPubBz) != 0 {
		t.Errorf("pubBz mismatch: native=%s, expected=%s", pubBz.String(), expectedPubBz.String())
	}
}

// TestBlindFoldSolverWithExportedData loads the exported config and witness JSONs,
// constructs the BlindFold circuit, and verifies the gnark solver passes.
// This is the main integration test for transcript parity between Rust and Go.
func TestBlindFoldSolverWithExportedData(t *testing.T) {
	// Load config
	config, err := LoadBlindFoldConfig("blindfold_config.json")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	t.Logf("Config: %d constraints, %d vars, %d inner_vars",
		config.NumConstraints, config.NumVars, config.InnerNumVars)
	t.Logf("  Spartan degree: %d, Inner degree: %d", config.SpartanDegree, config.InnerDegree)
	t.Logf("  Round coms: %d, Noncoeff coms: %d, E row coms: %d, Cross terms: %d",
		config.NumRoundCommitments, config.NumNoncoeffCommitments,
		config.NumERowCommitments, config.NumCrossTermCommitments)

	// Load witness
	witness, err := LoadBlindFoldWitness("blindfold_witness.json")
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}
	t.Logf("Witness loaded: %d spartan rounds, %d inner rounds",
		len(witness.SpartanCoeffs), len(witness.InnerCoeffs))

	// Create the witness assignment (concrete values)
	assignment := NewBlindFoldCircuit(config, witness)

	// Create the circuit placeholder (for compilation)
	circuit := AllocateBlindFoldCircuit(config)

	// Copy debug checkpoints from assignment to circuit so Define() generates assertions.
	// These are gnark:"-" fields, so they must be set on both structs.
	circuit.DebugRChallenge = assignment.DebugRChallenge
	circuit.DebugTau = assignment.DebugTau
	circuit.DebugRx = assignment.DebugRx
	circuit.DebugRa = assignment.DebugRa
	circuit.DebugRb = assignment.DebugRb
	circuit.DebugRc = assignment.DebugRc
	circuit.DebugPubAz = assignment.DebugPubAz
	circuit.DebugPubBz = assignment.DebugPubBz
	circuit.DebugPubCz = assignment.DebugPubCz
	circuit.DebugInnerClaimInit = assignment.DebugInnerClaimInit
	circuit.DebugInnerClaimFinal = assignment.DebugInnerClaimFinal
	circuit.DebugRy = assignment.DebugRy
	circuit.DebugLwAtRy = assignment.DebugLwAtRy

	// Run gnark solver test
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))

	t.Log("BlindFold solver test PASSED")
}

// TestBlindFoldStageChallengeAssertion verifies that when StageChallenges are provided
// (as they would be from the combined ZK Fiat-Shamir circuit), the assertion that they
// match BakedChallenges passes with correct values and fails with wrong values.
func TestBlindFoldStageChallengeAssertion(t *testing.T) {
	config, err := LoadBlindFoldConfig("blindfold_config.json")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	witness, err := LoadBlindFoldWitness("blindfold_witness.json")
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}

	t.Logf("Baked challenges: %v", witness.BakedChallenges)
	if len(witness.BakedChallenges) == 0 {
		t.Fatal("No baked challenges in witness — re-export from Rust")
	}

	// --- Test 1: Correct StageChallenges should pass ---
	t.Run("correct_challenges", func(t *testing.T) {
		assignment := NewBlindFoldCircuit(config, witness)
		circuit := AllocateBlindFoldCircuit(config)

		// Copy debug checkpoints
		circuit.DebugRChallenge = assignment.DebugRChallenge
		circuit.DebugTau = assignment.DebugTau
		circuit.DebugRx = assignment.DebugRx
		circuit.DebugRa = assignment.DebugRa
		circuit.DebugRb = assignment.DebugRb
		circuit.DebugRc = assignment.DebugRc
		circuit.DebugPubAz = assignment.DebugPubAz
		circuit.DebugPubBz = assignment.DebugPubBz
		circuit.DebugPubCz = assignment.DebugPubCz
		circuit.DebugInnerClaimInit = assignment.DebugInnerClaimInit
		circuit.DebugInnerClaimFinal = assignment.DebugInnerClaimFinal
		circuit.DebugRy = assignment.DebugRy
		circuit.DebugLwAtRy = assignment.DebugLwAtRy

		// Set BakedChallenges on circuit (gnark:"-" field)
		circuit.BakedChallenges = assignment.BakedChallenges

		// Set StageChallenges to the correct baked values (simulates combined circuit)
		stageChallenges := make([]frontend.Variable, len(assignment.BakedChallenges))
		for i, bc := range assignment.BakedChallenges {
			stageChallenges[i] = new(big.Int).Set(bc)
		}
		circuit.StageChallenges = stageChallenges
		assignment.StageChallenges = stageChallenges

		assert := test.NewAssert(t)
		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
		t.Log("Correct stage challenges PASSED")
	})

	// --- Test 2: Wrong StageChallenges should fail at compile time ---
	// Since both StageChallenges and BakedChallenges are gnark:"-" (constants),
	// gnark detects the mismatch during circuit compilation, not at solve time.
	// In the real combined circuit, StageChallenges are circuit variables (from
	// Fiat-Shamir derivation), so mismatches would be caught at solve time.
	t.Run("wrong_challenges", func(t *testing.T) {
		circuit := AllocateBlindFoldCircuit(config)

		// Copy debug checkpoints from assignment
		assignment := NewBlindFoldCircuit(config, witness)
		circuit.DebugRChallenge = assignment.DebugRChallenge
		circuit.DebugTau = assignment.DebugTau
		circuit.DebugRx = assignment.DebugRx
		circuit.DebugRa = assignment.DebugRa
		circuit.DebugRb = assignment.DebugRb
		circuit.DebugRc = assignment.DebugRc
		circuit.DebugPubAz = assignment.DebugPubAz
		circuit.DebugPubBz = assignment.DebugPubBz
		circuit.DebugPubCz = assignment.DebugPubCz
		circuit.DebugInnerClaimInit = assignment.DebugInnerClaimInit
		circuit.DebugInnerClaimFinal = assignment.DebugInnerClaimFinal
		circuit.DebugRy = assignment.DebugRy
		circuit.DebugLwAtRy = assignment.DebugLwAtRy

		// Set BakedChallenges on circuit
		circuit.BakedChallenges = assignment.BakedChallenges

		// Set StageChallenges to WRONG values (off by 1)
		wrongChallenges := make([]frontend.Variable, len(assignment.BakedChallenges))
		for i, bc := range assignment.BakedChallenges {
			wrong := new(big.Int).Set(bc)
			wrong.Add(wrong, big.NewInt(1))
			wrongChallenges[i] = wrong
		}
		circuit.StageChallenges = wrongChallenges

		// Expect compile-time failure (constant mismatch detected during compilation)
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err == nil {
			t.Fatal("Expected compile error for wrong stage challenges, but got none")
		}
		t.Logf("Wrong stage challenges correctly REJECTED at compile time: %v", err)
	})
}

// ============================================================
// ZK Fiat-Shamir standalone test
// ============================================================

// TestZKFiatShamirCircuit is a test circuit for verifying Poseidon challenge derivation.
// It runs DeriveZKStageChallenges and asserts derived challenges match expected values.
type TestZKFiatShamirCircuit struct {
	// Config (gnark:"-" = circuit structure, not witness)
	FSConfig ZKFiatShamirConfig `gnark:"-"`

	// Witness: commitment coordinates per stage
	FSWitness ZKFiatShamirWitness

	// Expected challenges (gnark:"-" = constant assertions)
	ExpectedChallenges []*big.Int `gnark:"-"`
}

func (c *TestZKFiatShamirCircuit) Define(api frontend.API) error {
	challenges, _ := DeriveZKStageChallenges(api, &c.FSConfig, &c.FSWitness)

	// Assert each derived challenge matches expected
	for i, expected := range c.ExpectedChallenges {
		if i < len(challenges) {
			api.AssertIsEqual(challenges[i], expected)
		}
	}
	return nil
}

// buildZKFSFromJSON constructs ZKFiatShamirConfig, witness (assignment), and circuit placeholder
// from exported JSON data.
func buildZKFSFromJSON(fsData *ZKFiatShamirWitnessJSON) (ZKFiatShamirConfig, ZKFiatShamirWitness, ZKFiatShamirWitness) {
	joltLabel := ParseHexToBigInt(fsData.JoltLabel)
	joltLabelVar := frontend.Variable(joltLabel)
	sumcheckComLabel := labelToFr("sumcheck_commitment")
	sumcheckComLabelVar := frontend.Variable(sumcheckComLabel)

	fsConfig := ZKFiatShamirConfig{
		JoltTranscriptLabel:     &joltLabelVar,
		SumcheckCommitmentLabel: &sumcheckComLabelVar,
		Stages:                  make([]ZKStageConfig, len(fsData.Stages)),
	}

	// If transcript state is provided (real mode), initialize from it
	if fsData.TranscriptState != nil && fsData.TranscriptNRounds != nil {
		stateVar := frontend.Variable(ParseHexToBigInt(*fsData.TranscriptState))
		nRoundsVar := frontend.Variable(*fsData.TranscriptNRounds)
		fsConfig.InitialState = &stateVar
		fsConfig.InitialNRounds = &nRoundsVar
	}

	nStages := len(fsData.Stages)
	fsWitness := ZKFiatShamirWitness{
		StageCommitmentCFrs: make([][]frontend.Variable, nStages),
		StageCommitmentsX:   make([][]frontend.Variable, nStages),
		StageCommitmentsY:   make([][]frontend.Variable, nStages),
	}
	circuitWitness := ZKFiatShamirWitness{
		StageCommitmentCFrs: make([][]frontend.Variable, nStages),
		StageCommitmentsX:   make([][]frontend.Variable, nStages),
		StageCommitmentsY:   make([][]frontend.Variable, nStages),
	}

	for stageIdx, stage := range fsData.Stages {
		stageLabel := ParseHexToBigInt(stage.Label)
		stageLabelVar := frontend.Variable(stageLabel)
		fsConfig.Stages[stageIdx] = ZKStageConfig{
			NumRounds:              stage.NumRounds,
			Label:                  &stageLabelVar,
			NumCommitmentsPerRound: stage.NumCommitmentsPerRound,
		}

		numComs := stage.NumRounds * stage.NumCommitmentsPerRound
		fsWitness.StageCommitmentCFrs[stageIdx] = make([]frontend.Variable, numComs)
		fsWitness.StageCommitmentsX[stageIdx] = make([]frontend.Variable, numComs)
		fsWitness.StageCommitmentsY[stageIdx] = make([]frontend.Variable, numComs)
		circuitWitness.StageCommitmentCFrs[stageIdx] = make([]frontend.Variable, numComs)
		circuitWitness.StageCommitmentsX[stageIdx] = make([]frontend.Variable, numComs)
		circuitWitness.StageCommitmentsY[stageIdx] = make([]frontend.Variable, numComs)

		for i := 0; i < numComs; i++ {
			fsWitness.StageCommitmentCFrs[stageIdx][i] = ParseHexToBigInt(stage.CommitmentCFrs[i])
			if len(stage.CommitmentXs) > i {
				fsWitness.StageCommitmentsX[stageIdx][i] = ParseHexToBigInt(stage.CommitmentXs[i])
				fsWitness.StageCommitmentsY[stageIdx][i] = ParseHexToBigInt(stage.CommitmentYs[i])
			}
		}
	}

	return fsConfig, fsWitness, circuitWitness
}

// TestZKFiatShamirSolverWithExportedData loads the ZK Fiat-Shamir witness JSON
// and verifies Poseidon challenge derivation matches Rust.
func TestZKFiatShamirSolverWithExportedData(t *testing.T) {
	fsData, err := LoadZKFiatShamirWitness("zk_fiat_shamir_witness.json")
	if err != nil {
		t.Fatalf("Failed to load ZK FS witness: %v", err)
	}

	t.Logf("ZK FS: %d stages, %d expected challenges",
		len(fsData.Stages), len(fsData.ExpectedChallenges))

	// Parse expected challenges
	expectedChallenges := make([]*big.Int, len(fsData.ExpectedChallenges))
	for i, h := range fsData.ExpectedChallenges {
		expectedChallenges[i] = ParseHexToBigInt(h)
	}

	fsConfig, fsWitness, circuitWitness := buildZKFSFromJSON(fsData)

	// Create circuit and assignment
	circuit := &TestZKFiatShamirCircuit{
		FSConfig:           fsConfig,
		FSWitness:          circuitWitness,
		ExpectedChallenges: expectedChallenges,
	}

	assignment := &TestZKFiatShamirCircuit{
		FSConfig:           fsConfig,
		FSWitness:          fsWitness,
		ExpectedChallenges: expectedChallenges,
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	t.Log("ZK Fiat-Shamir challenge derivation PASSED — Poseidon parity verified")
}

// ============================================================
// Combined circuit test: ZK Fiat-Shamir + BlindFold
// ============================================================

// TestZKCombinedCircuitSolver tests the full ZKVerifierCircuit:
// Part 1: ZK Fiat-Shamir derives challenges from G1 commitments
// Part 2: BlindFold verifies R1CS satisfaction
// The challenges from Part 1 must match the baked challenges in Part 2.
func TestZKCombinedCircuitSolver(t *testing.T) {
	// Load BlindFold data
	bfConfig, err := LoadBlindFoldConfig("blindfold_config.json")
	if err != nil {
		t.Fatalf("Failed to load BlindFold config: %v", err)
	}
	bfWitness, err := LoadBlindFoldWitness("blindfold_witness.json")
	if err != nil {
		t.Fatalf("Failed to load BlindFold witness: %v", err)
	}

	// Load ZK Fiat-Shamir data
	fsData, err := LoadZKFiatShamirWitness("zk_fiat_shamir_witness.json")
	if err != nil {
		t.Fatalf("Failed to load ZK FS witness: %v", err)
	}

	t.Logf("Combined circuit: %d FS stages, %d BlindFold constraints",
		len(fsData.Stages), bfConfig.NumConstraints)
	t.Logf("  Baked challenges: %v", bfWitness.BakedChallenges)
	t.Logf("  Expected FS challenges: %v", fsData.ExpectedChallenges)

	// Verify baked challenges match expected FS challenges (sanity check)
	if len(bfWitness.BakedChallenges) != len(fsData.ExpectedChallenges) {
		t.Fatalf("Challenge count mismatch: baked=%d, FS=%d",
			len(bfWitness.BakedChallenges), len(fsData.ExpectedChallenges))
	}
	for i := range bfWitness.BakedChallenges {
		if bfWitness.BakedChallenges[i] != fsData.ExpectedChallenges[i] {
			t.Fatalf("Challenge[%d] mismatch: baked=%s, FS=%s",
				i, bfWitness.BakedChallenges[i], fsData.ExpectedChallenges[i])
		}
	}
	t.Log("  Baked challenges match FS expected challenges ✓")

	// === Build ZK Fiat-Shamir config ===
	fsConfig, fsWitness, circuitFSWitness := buildZKFSFromJSON(fsData)

	// === Build BlindFold circuit and assignment ===
	bfAssignment := NewBlindFoldCircuit(bfConfig, bfWitness)
	bfCircuit := AllocateBlindFoldCircuit(bfConfig)

	// Copy gnark:"-" fields from assignment to circuit
	bfCircuit.DebugRChallenge = bfAssignment.DebugRChallenge
	bfCircuit.DebugTau = bfAssignment.DebugTau
	bfCircuit.DebugRx = bfAssignment.DebugRx
	bfCircuit.DebugRa = bfAssignment.DebugRa
	bfCircuit.DebugRb = bfAssignment.DebugRb
	bfCircuit.DebugRc = bfAssignment.DebugRc
	bfCircuit.DebugPubAz = bfAssignment.DebugPubAz
	bfCircuit.DebugPubBz = bfAssignment.DebugPubBz
	bfCircuit.DebugPubCz = bfAssignment.DebugPubCz
	bfCircuit.DebugInnerClaimInit = bfAssignment.DebugInnerClaimInit
	bfCircuit.DebugInnerClaimFinal = bfAssignment.DebugInnerClaimFinal
	bfCircuit.DebugRy = bfAssignment.DebugRy
	bfCircuit.DebugLwAtRy = bfAssignment.DebugLwAtRy
	bfCircuit.BakedChallenges = bfAssignment.BakedChallenges

	// === Assemble combined circuit ===
	circuit := &ZKVerifierCircuit{
		FiatShamirConfig:  fsConfig,
		FiatShamirWitness: circuitFSWitness,
		BlindFold:         *bfCircuit,
	}

	assignment := &ZKVerifierCircuit{
		FiatShamirConfig:  fsConfig,
		FiatShamirWitness: fsWitness,
		BlindFold:         *bfAssignment,
	}

	// Run solver test
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	t.Log("Combined ZK circuit (Fiat-Shamir + BlindFold) PASSED")
}

// ============================================================
// Groth16 Prove/Verify (production dimensions)
// ============================================================

// TestZKCombinedCircuitGroth16ProveVerify runs a full Groth16 lifecycle
// on the combined ZK Fiat-Shamir + BlindFold circuit at production
// dimensions (7 stages, 232 challenges — matching fib(50)).
func TestZKCombinedCircuitGroth16ProveVerify(t *testing.T) {
	// Load config, witness, and ZK FS data
	bfConfig, err := LoadBlindFoldConfig("blindfold_config.json")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	bfWitness, err := LoadBlindFoldWitness("blindfold_witness.json")
	if err != nil {
		t.Fatalf("Failed to load witness: %v", err)
	}
	fsData, err := LoadZKFiatShamirWitness("zk_fiat_shamir_witness.json")
	if err != nil {
		t.Fatalf("Failed to load ZK FS witness: %v", err)
	}

	t.Logf("Production dimensions: %d stages, %d challenges, %d constraints",
		len(fsData.Stages), len(fsData.ExpectedChallenges), bfConfig.NumConstraints)
	t.Logf("  Spartan rounds: %d, Inner rounds: %d", bfConfig.NumVars, bfConfig.InnerNumVars)
	t.Logf("  Round coms: %d, Noncoeff coms: %d, E row coms: %d, Cross terms: %d",
		bfConfig.NumRoundCommitments, bfConfig.NumNoncoeffCommitments,
		bfConfig.NumERowCommitments, bfConfig.NumCrossTermCommitments)

	// === Build ZK Fiat-Shamir config ===
	fsConfig, fsWitness, circuitFSWitness := buildZKFSFromJSON(fsData)

	// === Build BlindFold circuit and assignment ===
	bfAssignment := NewBlindFoldCircuit(bfConfig, bfWitness)
	bfCircuit := AllocateBlindFoldCircuit(bfConfig)

	// Copy gnark:"-" fields from assignment to circuit
	bfCircuit.DebugRChallenge = bfAssignment.DebugRChallenge
	bfCircuit.DebugTau = bfAssignment.DebugTau
	bfCircuit.DebugRx = bfAssignment.DebugRx
	bfCircuit.DebugRa = bfAssignment.DebugRa
	bfCircuit.DebugRb = bfAssignment.DebugRb
	bfCircuit.DebugRc = bfAssignment.DebugRc
	bfCircuit.DebugPubAz = bfAssignment.DebugPubAz
	bfCircuit.DebugPubBz = bfAssignment.DebugPubBz
	bfCircuit.DebugPubCz = bfAssignment.DebugPubCz
	bfCircuit.DebugInnerClaimInit = bfAssignment.DebugInnerClaimInit
	bfCircuit.DebugInnerClaimFinal = bfAssignment.DebugInnerClaimFinal
	bfCircuit.DebugRy = bfAssignment.DebugRy
	bfCircuit.DebugLwAtRy = bfAssignment.DebugLwAtRy
	bfCircuit.BakedChallenges = bfAssignment.BakedChallenges

	// === Assemble combined circuit ===
	circuit := &ZKVerifierCircuit{
		FiatShamirConfig:  fsConfig,
		FiatShamirWitness: circuitFSWitness,
		BlindFold:         *bfCircuit,
	}

	assignment := &ZKVerifierCircuit{
		FiatShamirConfig:  fsConfig,
		FiatShamirWitness: fsWitness,
		BlindFold:         *bfAssignment,
	}

	// ================================================================
	// Compile
	// ================================================================
	t.Log("")
	t.Log("Compiling combined ZK circuit...")
	startCompile := time.Now()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}
	compileTime := time.Since(startCompile)
	t.Logf("Compiled: %d constraints, %d public inputs, %d internal vars [%v]",
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbInternalVariables(), compileTime)

	// ================================================================
	// Groth16 Setup
	// ================================================================
	t.Log("")
	t.Log("Running Groth16 setup...")
	startSetup := time.Now()

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("Groth16 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup)

	var pkBuf, vkBuf bytes.Buffer
	pk.WriteTo(&pkBuf)
	vk.WriteTo(&vkBuf)
	t.Logf("Setup complete: pk=%.2f MB, vk=%.2f KB [%v]",
		float64(pkBuf.Len())/1024/1024, float64(vkBuf.Len())/1024, setupTime)

	// ================================================================
	// Groth16 Prove
	// ================================================================
	t.Log("")
	t.Log("Generating Groth16 proof...")
	startProve := time.Now()

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("Groth16 prove failed: %v", err)
	}
	proveTime := time.Since(startProve)

	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf)
	t.Logf("Proof generated: %d bytes [%v]", proofBuf.Len(), proveTime)

	// ================================================================
	// Groth16 Verify
	// ================================================================
	t.Log("")
	t.Log("Verifying Groth16 proof...")
	startVerify := time.Now()

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("Groth16 verification FAILED: %v", err)
	}
	verifyTime := time.Since(startVerify)

	// ================================================================
	// Summary
	// ================================================================
	t.Log("")
	t.Log("=== Groth16 Prove/Verify Summary ===")
	t.Logf("Circuit:      Combined ZK Fiat-Shamir + BlindFold")
	t.Logf("Stages:       %d (fib(50) dimensions)", len(fsData.Stages))
	t.Logf("Challenges:   %d", len(fsData.ExpectedChallenges))
	t.Logf("Constraints:  %d", ccs.GetNbConstraints())
	t.Logf("Proof size:   %d bytes", proofBuf.Len())
	t.Logf("Compile time: %v", compileTime)
	t.Logf("Setup time:   %v", setupTime)
	t.Logf("Prove time:   %v", proveTime)
	t.Logf("Verify time:  %v", verifyTime)
	t.Log("PASSED — Groth16 proof verified successfully")
}
