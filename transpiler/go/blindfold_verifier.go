// BlindFold verifier circuit for gnark.
//
// Implements the Nova folding + Spartan sumcheck verification protocol.
// This makes the Jolt proof zero-knowledge by proving R1CS satisfaction
// via a BlindFold proof instead of exposing polynomial coefficients.
//
// Protocol steps (13 total, 3 deferred for PCS):
//   1. Reconstruct real instance (u=1, commitments from witness)
//   2. Absorb instances to transcript (hash G1 coordinates)
//   3. Derive folding challenge r
//   4. Fold instances (ScalarMul + Add on G1 points)
//   5. Eval commitment check — DEFERRED (PCS)
//   6. Spartan outer sumcheck (degree 3)
//   7. Final Spartan claims (absorb az_r, bz_r, cz_r)
//   8. Public contributions (sparse R1CS eval with eq polynomial)
//   9. Inner sumcheck (degree 2)
//  10. E opening verification — DEFERRED (PCS)
//  11. Outer claim check: eq(tau,rx)*(Az*Bz - u*Cz) - E(r) = claim
//  12. W opening verification — DEFERRED (PCS)
//  13. Inner claim check: L_w(ry) * w_ry = inner_claim
package jolt_verifier

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_grumpkin"
	"jolt_verifier/poseidon"
)

// BlindFoldCircuit implements the BlindFold verification in gnark.
// Array sizes are determined by config (loaded from JSON at circuit instantiation).
type BlindFoldCircuit struct {
	// === Config: dimensions and R1CS matrices (constant per proof) ===
	Config BlindFoldConfig `gnark:"-"` // Not a witness

	// Parsed R1CS matrices (derived from Config at setup)
	r1csA []SparseEntry `gnark:"-"`
	r1csB []SparseEntry `gnark:"-"`
	r1csC []SparseEntry `gnark:"-"`

	// === Witness: Random instance ===
	RandomU         frontend.Variable   `gnark:"random_u"`
	RandomRoundX    []frontend.Variable `gnark:"random_round_x"`
	RandomRoundY    []frontend.Variable `gnark:"random_round_y"`
	RandomNoncoeffX []frontend.Variable `gnark:"random_noncoeff_x"`
	RandomNoncoeffY []frontend.Variable `gnark:"random_noncoeff_y"`
	RandomERowX     []frontend.Variable `gnark:"random_e_row_x"`
	RandomERowY     []frontend.Variable `gnark:"random_e_row_y"`
	RandomEvalX     []frontend.Variable `gnark:"random_eval_x"`
	RandomEvalY     []frontend.Variable `gnark:"random_eval_y"`

	// === Witness: Real instance commitments (from stages 1-7) ===
	RealRoundX    []frontend.Variable `gnark:"real_round_x"`
	RealRoundY    []frontend.Variable `gnark:"real_round_y"`
	RealNoncoeffX []frontend.Variable `gnark:"real_noncoeff_x"`
	RealNoncoeffY []frontend.Variable `gnark:"real_noncoeff_y"`
	RealEvalX     []frontend.Variable `gnark:"real_eval_x"`
	RealEvalY     []frontend.Variable `gnark:"real_eval_y"`

	// === Witness: Cross-term commitments ===
	CrossTermX []frontend.Variable `gnark:"cross_term_x"`
	CrossTermY []frontend.Variable `gnark:"cross_term_y"`

	// === Witness: BN254 compressed Fr for Poseidon transcript absorption ===
	// Each BN254 G1 point → serialize_compressed (32 bytes) → from_le_bytes_mod_order → Fr.
	// Used instead of Grumpkin (x,y) for transcript hashing (1 hash per point vs 2).
	RandomRoundCFr    []frontend.Variable `gnark:"random_round_cfr"`
	RandomNoncoeffCFr []frontend.Variable `gnark:"random_noncoeff_cfr"`
	RandomERowCFr     []frontend.Variable `gnark:"random_e_row_cfr"`
	RandomEvalCFr     []frontend.Variable `gnark:"random_eval_cfr"`
	RealRoundCFr      []frontend.Variable `gnark:"real_round_cfr"`
	RealNoncoeffCFr   []frontend.Variable `gnark:"real_noncoeff_cfr"`
	RealEvalCFr       []frontend.Variable `gnark:"real_eval_cfr"`
	CrossTermCFr      []frontend.Variable `gnark:"cross_term_cfr"`

	// === Witness: Spartan outer sumcheck ===
	// SpartanCoeffs[round][coeff_idx] — coefficients except linear term
	SpartanCoeffs [][]frontend.Variable `gnark:"spartan_coeffs"`

	// === Witness: Final Spartan claims ===
	AzR frontend.Variable `gnark:"az_r"`
	BzR frontend.Variable `gnark:"bz_r"`
	CzR frontend.Variable `gnark:"cz_r"`

	// === Witness: Inner sumcheck ===
	InnerCoeffs [][]frontend.Variable `gnark:"inner_coeffs"`

	// === Trusted witness (deferred PCS verification) ===
	ER  frontend.Variable `gnark:"e_r"`
	WRy frontend.Variable `gnark:"w_ry"`

	// === Witness: Folded u (result of folding: u_folded = 1 + r * random_u) ===
	// Provided as witness for efficiency; verified by folding step 4.
	FoldedU frontend.Variable `gnark:"folded_u"`

	// === Baked challenge values (stage 1-7 round challenges baked into R1CS) ===
	// These are the γ values used as evaluation points in R1CS constraints.
	// Exported from Rust's BakedPublicInputs.challenges.
	BakedChallenges []*big.Int `gnark:"-"`

	// === Stage challenges (injected by combined circuit from ZK Fiat-Shamir) ===
	// When set, Define() asserts these match BakedChallenges, proving the R1CS
	// was built from correctly derived Fiat-Shamir challenges.
	StageChallenges []frontend.Variable `gnark:"-"`

	// === Transcript label constants (pre-computed, not witness) ===
	LabelBlindFold             *big.Int `gnark:"-"`
	LabelRealInstance          *big.Int `gnark:"-"`
	LabelRandomInstance        *big.Int `gnark:"-"`
	LabelU                     *big.Int `gnark:"-"`
	LabelRoundComs             *big.Int `gnark:"-"`
	LabelNoncoeff              *big.Int `gnark:"-"`
	LabelERows                 *big.Int `gnark:"-"`
	LabelEvalComs              *big.Int `gnark:"-"`
	LabelCrossTerm             *big.Int `gnark:"-"`
	LabelSpartan               *big.Int `gnark:"-"`
	LabelSumcheckPoly          *big.Int `gnark:"-"`
	LabelAzBzCz                *big.Int `gnark:"-"`
	LabelInnerSumcheckPoly     *big.Int `gnark:"-"`

	// Debug checkpoints (constant, not witness — for transcript parity verification)
	DebugRChallenge     *big.Int   `gnark:"-"`
	DebugTau            []*big.Int `gnark:"-"`
	DebugRx             []*big.Int `gnark:"-"`
	DebugRa             *big.Int   `gnark:"-"`
	DebugRb             *big.Int   `gnark:"-"`
	DebugRc             *big.Int   `gnark:"-"`
	DebugPubAz          *big.Int   `gnark:"-"`
	DebugPubBz          *big.Int   `gnark:"-"`
	DebugPubCz          *big.Int   `gnark:"-"`
	DebugInnerClaimInit *big.Int   `gnark:"-"`
	DebugRy             []*big.Int `gnark:"-"`
	DebugLwAtRy          *big.Int   `gnark:"-"`
	DebugInnerClaimFinal *big.Int   `gnark:"-"`
}

// NewBlindFoldCircuit creates a BlindFold circuit from config and witness JSON.
func NewBlindFoldCircuit(config *BlindFoldConfig, witness *BlindFoldWitnessJSON) *BlindFoldCircuit {
	c := &BlindFoldCircuit{
		Config: *config,
		r1csA:  ParseSparseEntries(config.R1CSA),
		r1csB:  ParseSparseEntries(config.R1CSB),
		r1csC:  ParseSparseEntries(config.R1CSC),
	}

	// Parse witness: random instance
	c.RandomU = ParseHexToBigInt(witness.RandomU)
	c.RandomRoundX, c.RandomRoundY = ParseG1Points(witness.RandomRoundComs)
	c.RandomNoncoeffX, c.RandomNoncoeffY = ParseG1Points(witness.RandomNoncoeff)
	c.RandomERowX, c.RandomERowY = ParseG1Points(witness.RandomERows)
	c.RandomEvalX, c.RandomEvalY = ParseG1Points(witness.RandomEvalComs)

	// Parse witness: real instance
	c.RealRoundX, c.RealRoundY = ParseG1Points(witness.RealRoundComs)
	c.RealNoncoeffX, c.RealNoncoeffY = ParseG1Points(witness.RealNoncoeffComs)
	c.RealEvalX, c.RealEvalY = ParseG1Points(witness.RealEvalComs)

	// Parse witness: cross-term
	c.CrossTermX, c.CrossTermY = ParseG1Points(witness.CrossTermComs)

	// Parse witness: BN254 compressed Fr for transcript absorption
	c.RandomRoundCFr = ParseG1PointsCFr(witness.RandomRoundComs)
	c.RandomNoncoeffCFr = ParseG1PointsCFr(witness.RandomNoncoeff)
	c.RandomERowCFr = ParseG1PointsCFr(witness.RandomERows)
	c.RandomEvalCFr = ParseG1PointsCFr(witness.RandomEvalComs)
	c.RealRoundCFr = ParseG1PointsCFr(witness.RealRoundComs)
	c.RealNoncoeffCFr = ParseG1PointsCFr(witness.RealNoncoeffComs)
	c.RealEvalCFr = ParseG1PointsCFr(witness.RealEvalComs)
	c.CrossTermCFr = ParseG1PointsCFr(witness.CrossTermComs)

	// Parse witness: sumchecks
	c.SpartanCoeffs = ParseScalarMatrix(witness.SpartanCoeffs)
	c.AzR = ParseHexToBigInt(witness.AzR)
	c.BzR = ParseHexToBigInt(witness.BzR)
	c.CzR = ParseHexToBigInt(witness.CzR)
	c.InnerCoeffs = ParseScalarMatrix(witness.InnerCoeffs)

	// Parse trusted witness
	c.ER = ParseHexToBigInt(witness.ER)
	c.WRy = ParseHexToBigInt(witness.WRy)
	c.FoldedU = ParseHexToBigInt(witness.FoldedU)

	// Initialize transcript labels
	initLabels(c)

	// Parse debug checkpoints
	c.DebugRChallenge = ParseHexToBigInt(witness.DebugRChallenge)
	c.DebugTau = make([]*big.Int, len(witness.DebugTau))
	for i, h := range witness.DebugTau {
		c.DebugTau[i] = ParseHexToBigInt(h)
	}
	c.DebugRx = make([]*big.Int, len(witness.DebugRx))
	for i, h := range witness.DebugRx {
		c.DebugRx[i] = ParseHexToBigInt(h)
	}
	c.DebugRa = ParseHexToBigInt(witness.DebugRa)
	c.DebugRb = ParseHexToBigInt(witness.DebugRb)
	c.DebugRc = ParseHexToBigInt(witness.DebugRc)
	c.DebugPubAz = ParseHexToBigInt(witness.DebugPubAz)
	c.DebugPubBz = ParseHexToBigInt(witness.DebugPubBz)
	c.DebugPubCz = ParseHexToBigInt(witness.DebugPubCz)
	c.DebugInnerClaimInit = ParseHexToBigInt(witness.DebugInnerClaimInit)
	c.DebugRy = make([]*big.Int, len(witness.DebugRy))
	for i, h := range witness.DebugRy {
		c.DebugRy[i] = ParseHexToBigInt(h)
	}
	c.DebugLwAtRy = ParseHexToBigInt(witness.DebugLwAtRy)
	c.DebugInnerClaimFinal = ParseHexToBigInt(witness.DebugInnerClaimFinal)

	// Parse baked challenges
	if len(witness.BakedChallenges) > 0 {
		c.BakedChallenges = make([]*big.Int, len(witness.BakedChallenges))
		for i, h := range witness.BakedChallenges {
			c.BakedChallenges[i] = ParseHexToBigInt(h)
		}
	}

	return c
}

// AllocateBlindFoldCircuit creates an empty circuit with correctly-sized arrays for gnark compilation.
func AllocateBlindFoldCircuit(config *BlindFoldConfig) *BlindFoldCircuit {
	c := &BlindFoldCircuit{
		Config: *config,
		r1csA:  ParseSparseEntries(config.R1CSA),
		r1csB:  ParseSparseEntries(config.R1CSB),
		r1csC:  ParseSparseEntries(config.R1CSC),
	}

	// Allocate arrays with correct sizes
	c.RandomRoundX = make([]frontend.Variable, config.NumRoundCommitments)
	c.RandomRoundY = make([]frontend.Variable, config.NumRoundCommitments)
	c.RandomNoncoeffX = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RandomNoncoeffY = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RandomERowX = make([]frontend.Variable, config.NumERowCommitments)
	c.RandomERowY = make([]frontend.Variable, config.NumERowCommitments)
	c.RandomEvalX = make([]frontend.Variable, config.NumEvalCommitments)
	c.RandomEvalY = make([]frontend.Variable, config.NumEvalCommitments)

	c.RealRoundX = make([]frontend.Variable, config.NumRoundCommitments)
	c.RealRoundY = make([]frontend.Variable, config.NumRoundCommitments)
	c.RealNoncoeffX = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RealNoncoeffY = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RealEvalX = make([]frontend.Variable, config.NumEvalCommitments)
	c.RealEvalY = make([]frontend.Variable, config.NumEvalCommitments)

	c.CrossTermX = make([]frontend.Variable, config.NumCrossTermCommitments)
	c.CrossTermY = make([]frontend.Variable, config.NumCrossTermCommitments)

	// BN254 compressed Fr for transcript absorption
	c.RandomRoundCFr = make([]frontend.Variable, config.NumRoundCommitments)
	c.RandomNoncoeffCFr = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RandomERowCFr = make([]frontend.Variable, config.NumERowCommitments)
	c.RandomEvalCFr = make([]frontend.Variable, config.NumEvalCommitments)
	c.RealRoundCFr = make([]frontend.Variable, config.NumRoundCommitments)
	c.RealNoncoeffCFr = make([]frontend.Variable, config.NumNoncoeffCommitments)
	c.RealEvalCFr = make([]frontend.Variable, config.NumEvalCommitments)
	c.CrossTermCFr = make([]frontend.Variable, config.NumCrossTermCommitments)

	// Spartan: [num_vars rounds][spartan_degree coeffs]
	c.SpartanCoeffs = make([][]frontend.Variable, config.NumVars)
	for i := range c.SpartanCoeffs {
		c.SpartanCoeffs[i] = make([]frontend.Variable, config.SpartanDegree)
	}

	// Inner: [inner_num_vars rounds][inner_degree coeffs]
	c.InnerCoeffs = make([][]frontend.Variable, config.InnerNumVars)
	for i := range c.InnerCoeffs {
		c.InnerCoeffs[i] = make([]frontend.Variable, config.InnerDegree)
	}

	// Initialize transcript labels
	initLabels(c)

	return c
}

// Define implements the gnark circuit interface.
func (c *BlindFoldCircuit) Define(api frontend.API) error {
	// Initialize Grumpkin curve operations (GLV-optimized, ~1,775 constraints/scalar_mul)
	g, err := NewGrumpkinOps(api)
	if err != nil {
		return err
	}

	// ================================================================
	// Step 1: Reconstruct real instance
	// ================================================================
	// Real instance: u = 1, round_commitments and eval_commitments from witness.
	// E row commitments for real instance are identity (all zeros).

	// ================================================================
	// Step 2: Absorb instances into fresh transcript
	// ================================================================
	transcript := poseidon.NewFrTranscript(api, c.LabelBlindFold)

	// Append real instance
	transcript.AppendScalar(c.LabelRealInstance)
	// E row commitments for real instance are identity points → constant compressed Fr
	identityCfr := identityCompressedFr()
	zeroERowCFr := make([]frontend.Variable, c.Config.NumERowCommitments)
	for i := range zeroERowCFr {
		zeroERowCFr[i] = identityCfr
	}
	c.appendInstance(transcript, api,
		frontend.Variable(1), // u = 1 for real instance
		c.RealRoundCFr,
		c.RealNoncoeffCFr,
		zeroERowCFr,
		c.RealEvalCFr,
	)

	// Append random instance
	transcript.AppendScalar(c.LabelRandomInstance)
	c.appendInstance(transcript, api,
		c.RandomU,
		c.RandomRoundCFr,
		c.RandomNoncoeffCFr,
		c.RandomERowCFr,
		c.RandomEvalCFr,
	)

	// Append cross-term commitments
	transcript.AppendScalar(c.LabelCrossTerm)
	for i := 0; i < len(c.CrossTermCFr); i++ {
		transcript.AppendScalar(c.CrossTermCFr[i])
	}

	// ================================================================
	// Step 3: Derive folding challenge r
	// ================================================================
	r := transcript.ChallengeScalar()

	// DEBUG CHECKPOINT: verify folding challenge r matches Rust
	if c.DebugRChallenge != nil {
		api.AssertIsEqual(r, c.DebugRChallenge)
	}

	rSquared := api.Mul(r, r)

	// ================================================================
	// Step 4: Fold instances (GLV-optimized sw_grumpkin ScalarMul + Add)
	// ================================================================
	// u_folded = 1 + r * random_u
	expectedFoldedU := api.Add(1, api.Mul(r, c.RandomU))
	api.AssertIsEqual(c.FoldedU, expectedFoldedU)

	// Fold round commitments: folded[i] = real[i] + r * random[i]
	foldedRound := make([]*sw_grumpkin.G1Affine, len(c.RealRoundX))
	for i := range c.RealRoundX {
		realPt := MakePoint(c.RealRoundX[i], c.RealRoundY[i])
		randPt := MakePoint(c.RandomRoundX[i], c.RandomRoundY[i])
		scaled := g.ScalarMul(randPt, r)
		foldedRound[i] = g.Add(realPt, scaled)
	}

	// Fold noncoeff commitments: folded[i] = real[i] + r * random[i]
	foldedNoncoeff := make([]*sw_grumpkin.G1Affine, len(c.RealNoncoeffX))
	for i := range c.RealNoncoeffX {
		realPt := MakePoint(c.RealNoncoeffX[i], c.RealNoncoeffY[i])
		randPt := MakePoint(c.RandomNoncoeffX[i], c.RandomNoncoeffY[i])
		scaled := g.ScalarMul(randPt, r)
		foldedNoncoeff[i] = g.Add(realPt, scaled)
	}

	// Fold E row commitments: folded[i] = cross_term[i]*r + random_e[i]*r²
	// (real E = identity, so real contribution is omitted)
	foldedERow := make([]*sw_grumpkin.G1Affine, len(c.CrossTermX))
	for i := range c.CrossTermX {
		crossPt := MakePoint(c.CrossTermX[i], c.CrossTermY[i])
		randEPt := MakePoint(c.RandomERowX[i], c.RandomERowY[i])
		crossScaled := g.ScalarMul(crossPt, r)
		randScaled := g.ScalarMul(randEPt, rSquared)
		foldedERow[i] = g.Add(crossScaled, randScaled)
	}

	// Fold eval commitments: folded[i] = real[i] + r * random[i]
	foldedEval := make([]*sw_grumpkin.G1Affine, len(c.RealEvalX))
	for i := range c.RealEvalX {
		realPt := MakePoint(c.RealEvalX[i], c.RealEvalY[i])
		randPt := MakePoint(c.RandomEvalX[i], c.RandomEvalY[i])
		scaled := g.ScalarMul(randPt, r)
		foldedEval[i] = g.Add(realPt, scaled)
	}

	// Keep folded points for future PCS verification
	_ = foldedRound
	_ = foldedNoncoeff
	_ = foldedERow
	_ = foldedEval

	// ================================================================
	// Step 5: Eval commitment check — DEFERRED (PCS)
	// ================================================================
	// Skipped: folded_eval_outputs accepted as trusted witness

	// ================================================================
	// Step 6: Spartan outer sumcheck
	// ================================================================
	transcript.AppendScalar(c.LabelSpartan)

	// Derive tau challenges (sumcheck evaluation point)
	tau := make([]frontend.Variable, c.Config.NumVars)
	for i := range tau {
		tau[i] = transcript.ChallengeScalar()
	}

	// DEBUG CHECKPOINT: verify tau challenges match Rust
	for i, expected := range c.DebugTau {
		if expected != nil {
			api.AssertIsEqual(tau[i], expected)
		}
	}

	// Run sumcheck verification
	claim := frontend.Variable(0) // Initial claim = 0
	rx := make([]frontend.Variable, c.Config.NumVars)

	for round := 0; round < c.Config.NumVars; round++ {
		// Append coefficients to transcript
		transcript.AppendScalar(c.LabelSumcheckPoly)
		for _, coeff := range c.SpartanCoeffs[round] {
			transcript.AppendScalar(coeff)
		}

		// Decompress polynomial and verify
		poly := DecompressPoly(api, c.SpartanCoeffs[round], claim)

		// Verify: g(0) + g(1) = claim
		// g(0) = poly[0]
		// g(1) = sum of all coefficients
		gOfOne := frontend.Variable(0)
		for _, coeff := range poly {
			gOfOne = api.Add(gOfOne, coeff)
		}
		api.AssertIsEqual(api.Add(poly[0], gOfOne), claim)

		// Sample challenge
		rj := transcript.ChallengeScalar()
		rx[round] = rj

		// Evaluate at challenge for next round's claim
		claim = EvaluateHorner(api, poly, rj)
	}

	// DEBUG CHECKPOINT: verify rx challenges match Rust
	for i, expected := range c.DebugRx {
		if expected != nil {
			api.AssertIsEqual(rx[i], expected)
		}
	}

	// ================================================================
	// Step 7: Final Spartan claims
	// ================================================================
	transcript.AppendScalar(c.LabelAzBzCz)
	transcript.AppendScalar(c.AzR)
	transcript.AppendScalar(c.BzR)
	transcript.AppendScalar(c.CzR)

	ra := transcript.ChallengeScalar()
	rb := transcript.ChallengeScalar()
	rc := transcript.ChallengeScalar()

	// DEBUG CHECKPOINT: verify ra, rb, rc
	if c.DebugRa != nil {
		api.AssertIsEqual(ra, c.DebugRa)
	}
	if c.DebugRb != nil {
		api.AssertIsEqual(rb, c.DebugRb)
	}
	if c.DebugRc != nil {
		api.AssertIsEqual(rc, c.DebugRc)
	}

	// ================================================================
	// Step 8: Public contributions
	// ================================================================
	// Compute eq(rx, i) for all rows i
	eqRx := ComputeEqPolynomial(api, rx)

	// public_M = u * Σ_i A[i,0] * eq_rx[i]
	pubAz := SparsePublicContribution(api, c.r1csA, eqRx, c.FoldedU)
	pubBz := SparsePublicContribution(api, c.r1csB, eqRx, c.FoldedU)
	pubCz := SparsePublicContribution(api, c.r1csC, eqRx, c.FoldedU)

	// DEBUG CHECKPOINT: verify public contributions
	if c.DebugPubAz != nil {
		api.AssertIsEqual(pubAz, c.DebugPubAz)
	}
	if c.DebugPubBz != nil {
		api.AssertIsEqual(pubBz, c.DebugPubBz)
	}
	if c.DebugPubCz != nil {
		api.AssertIsEqual(pubCz, c.DebugPubCz)
	}

	// inner_claim = ra*(az_r - pub_az) + rb*(bz_r - pub_bz) + rc*(cz_r - pub_cz)
	innerClaim := api.Mul(ra, api.Sub(c.AzR, pubAz))
	innerClaim = api.Add(innerClaim, api.Mul(rb, api.Sub(c.BzR, pubBz)))
	innerClaim = api.Add(innerClaim, api.Mul(rc, api.Sub(c.CzR, pubCz)))

	// DEBUG CHECKPOINT: verify initial inner claim
	if c.DebugInnerClaimInit != nil {
		api.AssertIsEqual(innerClaim, c.DebugInnerClaimInit)
	}

	// ================================================================
	// Step 9: Inner sumcheck
	// ================================================================
	ry := make([]frontend.Variable, c.Config.InnerNumVars)

	for round := 0; round < c.Config.InnerNumVars; round++ {
		// Append coefficients to transcript
		transcript.AppendScalar(c.LabelInnerSumcheckPoly)
		for _, coeff := range c.InnerCoeffs[round] {
			transcript.AppendScalar(coeff)
		}

		// Decompress polynomial and verify
		poly := DecompressPoly(api, c.InnerCoeffs[round], innerClaim)

		// Verify: g(0) + g(1) = inner_claim
		gOfOne := frontend.Variable(0)
		for _, coeff := range poly {
			gOfOne = api.Add(gOfOne, coeff)
		}
		api.AssertIsEqual(api.Add(poly[0], gOfOne), innerClaim)

		// Sample challenge
		rj := transcript.ChallengeScalar()
		ry[round] = rj

		// Evaluate at challenge for next round's claim
		innerClaim = EvaluateHorner(api, poly, rj)
	}

	// ================================================================
	// Step 10: E opening verification — DEFERRED (PCS)
	// ================================================================
	// e_r accepted as trusted witness input

	// ================================================================
	// Step 11: Outer claim check
	// ================================================================
	// eq(tau, rx) * (Az*Bz - u*Cz - E(r)) = claim (from step 6)
	eqTauRx := ComputeEqSingle(api, tau, rx)
	azBz := api.Mul(c.AzR, c.BzR)
	uCz := api.Mul(c.FoldedU, c.CzR)
	outerExpected := api.Mul(eqTauRx, api.Sub(api.Sub(azBz, uCz), c.ER))
	api.AssertIsEqual(claim, outerExpected)

	// ================================================================
	// Step 12: W opening verification — DEFERRED (PCS)
	// ================================================================
	// w_ry accepted as trusted witness input

	// DEBUG CHECKPOINT: verify inner claim final
	if c.DebugInnerClaimFinal != nil {
		api.AssertIsEqual(innerClaim, c.DebugInnerClaimFinal)
	}

	// DEBUG CHECKPOINT: verify inner sumcheck challenges ry
	for i, expected := range c.DebugRy {
		if expected != nil {
			api.AssertIsEqual(ry[i], expected)
		}
	}

	// ================================================================
	// Step 13: Inner claim check
	// ================================================================
	// L_w(ry) * w_ry = inner_claim
	eqRy := ComputeEqPolynomial(api, ry)
	lwAtRy := ComputeLwAtRy(api, c.r1csA, c.r1csB, c.r1csC, eqRx, eqRy, ra, rb, rc)

	// DEBUG CHECKPOINT: verify L_w(ry)
	if c.DebugLwAtRy != nil {
		api.AssertIsEqual(lwAtRy, c.DebugLwAtRy)
	}

	expectedInner := api.Mul(lwAtRy, c.WRy)
	api.AssertIsEqual(innerClaim, expectedInner)

	// ================================================================
	// Stage challenge verification
	// ================================================================
	// When StageChallenges is provided (by the combined circuit's ZK Fiat-Shamir),
	// assert each derived challenge matches the baked challenge value that was used
	// to build the R1CS matrices. This proves the R1CS was built from correctly
	// derived Fiat-Shamir challenges.
	if len(c.StageChallenges) > 0 && len(c.BakedChallenges) > 0 {
		for i := 0; i < len(c.BakedChallenges) && i < len(c.StageChallenges); i++ {
			api.AssertIsEqual(c.StageChallenges[i], c.BakedChallenges[i])
		}
	}

	return nil
}

// appendInstance absorbs a RelaxedR1CS instance into the transcript.
// Mirrors Rust's append_instance_to_transcript using BN254 compressed serialization.
// Each commitment is absorbed as a single Fr value (compressed 32 bytes → from_le_bytes_mod_order).
func (c *BlindFoldCircuit) appendInstance(
	transcript *poseidon.FrTranscript,
	api frontend.API,
	u frontend.Variable,
	roundCFr []frontend.Variable,
	noncoeffCFr []frontend.Variable,
	eRowCFr []frontend.Variable,
	evalCFr []frontend.Variable,
) {
	// append_bytes("blindfold_u", u_bytes): packed label + scalar absorption
	transcript.AppendScalar(c.LabelU)
	transcript.AppendScalar(u)

	// append_commitments("blindfold_round_coms", &coms): packed label + per-point compressed Fr
	transcript.AppendScalar(c.LabelRoundComs)
	for _, cfr := range roundCFr {
		transcript.AppendScalar(cfr)
	}

	// append_commitments("blindfold_noncoeff", &coms)
	transcript.AppendScalar(c.LabelNoncoeff)
	for _, cfr := range noncoeffCFr {
		transcript.AppendScalar(cfr)
	}

	// append_commitments("blindfold_e_rows", &coms)
	transcript.AppendScalar(c.LabelERows)
	for _, cfr := range eRowCFr {
		transcript.AppendScalar(cfr)
	}

	// append_commitments("blindfold_eval_coms", &coms)
	transcript.AppendScalar(c.LabelEvalComs)
	for _, cfr := range evalCFr {
		transcript.AppendScalar(cfr)
	}
}
