package jolt_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_grumpkin"
	"github.com/consensys/gnark/std/math/emulated"
)

// ComputeEqPolynomial evaluates the eq polynomial at all boolean hypercube points.
// eq(r, x) = Π_i (r_i * x_i + (1-r_i)*(1-x_i))
// Returns 2^n values where n = len(challenges).
//
// Matches Jolt's EqPolynomial::evals convention: index b has bit k = x_k,
// so evals[b] = Π_k (r_k · bit_k(b) + (1-r_k)·(1-bit_k(b))).
func ComputeEqPolynomial(api frontend.API, challenges []frontend.Variable) []frontend.Variable {
	n := len(challenges)
	size := 1 << n
	evals := make([]frontend.Variable, size)
	evals[0] = frontend.Variable(1)

	// Process challenges in REVERSE order to match Rust's EqPolynomial::evals
	// big-endian convention: r[0] controls the MSB of the index.
	currentSize := 1
	for j := n - 1; j >= 0; j-- {
		r := challenges[j]
		oneMinusR := api.Sub(1, r)
		for i := currentSize - 1; i >= 0; i-- {
			evals[currentSize+i] = api.Mul(evals[i], r)
			evals[i] = api.Mul(evals[i], oneMinusR)
		}
		currentSize *= 2
	}

	return evals
}

// ComputeEqSingle computes eq(a, b) = Π_i (a_i * b_i + (1-a_i)*(1-b_i))
// where a and b are vectors of field elements (not necessarily bits).
func ComputeEqSingle(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	result := frontend.Variable(1)
	for i := 0; i < len(a); i++ {
		// eq_i = a_i * b_i + (1 - a_i) * (1 - b_i)
		// = 2*a_i*b_i - a_i - b_i + 1
		ab := api.Mul(a[i], b[i])
		term := api.Add(api.Mul(2, ab), 1)
		term = api.Sub(term, a[i])
		term = api.Sub(term, b[i])
		result = api.Mul(result, term)
	}
	return result
}

// DecompressPoly reconstructs the full polynomial from compressed coefficients.
//
// A compressed polynomial stores all coefficients EXCEPT the linear term (c_1).
// Given: coeffs_except_linear = [c_0, c_2, c_3, ..., c_d] and claim = g(0) + g(1),
// we recover c_1 using: g(0) + g(1) = claim
//
// g(0) = c_0
// g(1) = c_0 + c_1 + c_2 + ... + c_d
// So: claim = 2*c_0 + c_1 + c_2 + ... + c_d
// Thus: c_1 = claim - 2*c_0 - c_2 - c_3 - ... - c_d
//
// Returns the full polynomial coefficients [c_0, c_1, c_2, ..., c_d].
func DecompressPoly(api frontend.API, coeffsExceptLinear []frontend.Variable, claim frontend.Variable) []frontend.Variable {
	degree := len(coeffsExceptLinear) // degree = d, coeffs are [c_0, c_2, ..., c_d]
	fullCoeffs := make([]frontend.Variable, degree+1)

	c0 := coeffsExceptLinear[0]

	// c_1 = claim - 2*c_0 - c_2 - c_3 - ... - c_d
	c1 := api.Sub(claim, api.Mul(2, c0))
	for i := 1; i < degree; i++ {
		c1 = api.Sub(c1, coeffsExceptLinear[i])
	}

	fullCoeffs[0] = c0
	fullCoeffs[1] = c1
	for i := 1; i < degree; i++ {
		fullCoeffs[i+1] = coeffsExceptLinear[i]
	}

	return fullCoeffs
}

// EvaluateHorner evaluates polynomial at point using Horner's method.
// coeffs = [c_0, c_1, ..., c_d], returns c_0 + c_1*x + c_2*x^2 + ... + c_d*x^d.
func EvaluateHorner(api frontend.API, coeffs []frontend.Variable, point frontend.Variable) frontend.Variable {
	if len(coeffs) == 0 {
		return frontend.Variable(0)
	}
	// Horner: ((c_d * x + c_{d-1}) * x + c_{d-2}) * x + ... + c_0
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = api.MulAcc(coeffs[i], result, point)
	}
	return result
}

// SumcheckRoundVerify performs a single round of sumcheck verification.
// Returns the new claim (evaluation of the decompressed polynomial at challenge point).
func SumcheckRoundVerify(
	api frontend.API,
	coeffsExceptLinear []frontend.Variable,
	claim frontend.Variable,
	challenge frontend.Variable,
) frontend.Variable {
	// Decompress polynomial
	poly := DecompressPoly(api, coeffsExceptLinear, claim)

	// Verify sumcheck identity: g(0) + g(1) = claim
	// g(0) = c_0
	// g(1) = c_0 + c_1 + c_2 + ... + c_d
	sumAtOne := frontend.Variable(0)
	for _, c := range poly {
		sumAtOne = api.Add(sumAtOne, c)
	}
	api.AssertIsEqual(api.Add(poly[0], sumAtOne), claim)

	// Evaluate at challenge point for next claim
	return EvaluateHorner(api, poly, challenge)
}

// SparseMatVecDot computes the sparse dot product: Σ_{(i,_,v)} eq[i] * v
// for column-0 entries only (public contribution).
// entries: sparse matrix entries for column 0 only.
// eq: eq polynomial evaluations at the sumcheck point (length = num_constraints).
func SparsePublicContribution(api frontend.API, entries []SparseEntry, eq []frontend.Variable, u frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, e := range entries {
		if e.Col == 0 {
			// Contribution: eq[row] * coeff * u
			result = api.MulAcc(result, api.Mul(eq[e.Row], e.Coeff), u)
		}
	}
	return result
}

// SparseBilinearEval computes the sparse bilinear evaluation for witness columns (j > 0):
//
//	result = Σ_{(i,j,v) in entries, j>0} eq_rx[i] * eq_ry[j-1] * v
//
// Column indices are shifted by -1 because column 0 = u (public), and eq_ry
// is indexed over the witness dimensions [0, w_len). So R1CS column j maps to eq_ry[j-1].
// This matches Rust's bilinear_eval(..., col_start=1, ...) which uses eq_col[col - col_start].
func SparseBilinearEval(
	api frontend.API,
	entries []SparseEntry,
	eqRx []frontend.Variable,
	eqRy []frontend.Variable,
) frontend.Variable {
	result := frontend.Variable(0)
	for _, e := range entries {
		if e.Col > 0 {
			// Contribution: eq_rx[row] * eq_ry[col-1] * coeff
			// col-1 because R1CS column j (1-based witness) maps to eq_ry[j-1] (0-based)
			term := api.Mul(eqRx[e.Row], eqRy[e.Col-1])
			result = api.MulAcc(result, term, e.Coeff)
		}
	}
	return result
}

// ComputeLwAtRy evaluates L_w(ry) = ra * A'(ry) + rb * B'(ry) + rc * C'(ry)
// where A'(ry) = Σ_{(i,j,v) in A, j>0} eq_rx[i] * eq_ry[j] * v
//
// This is the bilinear sparse R1CS evaluation used in the inner sumcheck claim check.
func ComputeLwAtRy(
	api frontend.API,
	r1csA, r1csB, r1csC []SparseEntry,
	eqRx, eqRy []frontend.Variable,
	ra, rb, rc frontend.Variable,
) frontend.Variable {
	evalA := SparseBilinearEval(api, r1csA, eqRx, eqRy)
	evalB := SparseBilinearEval(api, r1csB, eqRx, eqRy)
	evalC := SparseBilinearEval(api, r1csC, eqRx, eqRy)

	// L_w = ra * A' + rb * B' + rc * C'
	result := api.Mul(ra, evalA)
	result = api.MulAcc(result, rb, evalB)
	result = api.MulAcc(result, rc, evalC)
	return result
}

// GrumpkinOps wraps sw_grumpkin curve and scalar field for G1 operations.
// Created once per Define() call, passed to functions that need G1 ops.
type GrumpkinOps struct {
	Curve       *sw_grumpkin.Curve
	ScalarField *emulated.Field[sw_grumpkin.ScalarField]
	API         frontend.API
}

// NewGrumpkinOps initializes the curve and scalar field for G1 operations.
func NewGrumpkinOps(api frontend.API) (*GrumpkinOps, error) {
	curve, err := sw_grumpkin.NewCurve(api)
	if err != nil {
		return nil, err
	}
	scalarField, err := emulated.NewField[sw_grumpkin.ScalarField](api)
	if err != nil {
		return nil, err
	}
	return &GrumpkinOps{
		Curve:       curve,
		ScalarField: scalarField,
		API:         api,
	}, nil
}

// NativeToScalar converts a native BN254 Fr element to a Grumpkin scalar.
// Uses bit decomposition: Fr → 254 bits → emulated Grumpkin scalar.
func (g *GrumpkinOps) NativeToScalar(s frontend.Variable) *emulated.Element[sw_grumpkin.ScalarField] {
	bits := g.API.ToBinary(s, 254)
	return g.ScalarField.FromBits(bits...)
}

// ScalarMul performs GLV-optimized scalar multiplication: result = s * P.
// ~1,775 constraints (vs ~3,500 for naive double-and-add).
func (g *GrumpkinOps) ScalarMul(p *sw_grumpkin.G1Affine, s frontend.Variable) *sw_grumpkin.G1Affine {
	scalar := g.NativeToScalar(s)
	return g.Curve.ScalarMul(p, scalar)
}

// Add adds two G1 points: result = P + Q.
func (g *GrumpkinOps) Add(p, q *sw_grumpkin.G1Affine) *sw_grumpkin.G1Affine {
	return g.Curve.Add(p, q)
}

// MakePoint creates a G1Affine from X, Y frontend.Variables.
func MakePoint(x, y frontend.Variable) *sw_grumpkin.G1Affine {
	return &sw_grumpkin.G1Affine{X: x, Y: y}
}
