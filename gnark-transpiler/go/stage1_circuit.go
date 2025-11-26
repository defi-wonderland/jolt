package jolt_verifier

import "github.com/consensys/gnark/frontend"

type Stage1Circuit struct {
	X_3 frontend.Variable `gnark:",public"`
	X_4 frontend.Variable `gnark:",public"`
	X_5 frontend.Variable `gnark:",public"`
	X_6 frontend.Variable `gnark:",public"`
	X_7 frontend.Variable `gnark:",public"`
	X_8 frontend.Variable `gnark:",public"`
	X_9 frontend.Variable `gnark:",public"`
	X_10 frontend.Variable `gnark:",public"`
	X_11 frontend.Variable `gnark:",public"`
	X_12 frontend.Variable `gnark:",public"`
	X_13 frontend.Variable `gnark:",public"`
	X_14 frontend.Variable `gnark:",public"`
	X_15 frontend.Variable `gnark:",public"`
	X_16 frontend.Variable `gnark:",public"`
	ExpectedFinalClaim frontend.Variable `gnark:",public"`
}

func (circuit *Stage1Circuit) Define(api frontend.API) error {
	// Power sum check: sum over symmetric domain must equal 0
	powerSumCheck := api.Add(api.Add(api.Add(api.Add(0, api.Mul(circuit.X_7, 10)), api.Mul(circuit.X_8, 5)), api.Mul(circuit.X_9, 85)), api.Mul(circuit.X_10, 125))
	api.AssertIsEqual(powerSumCheck, 0)

	// Sumcheck round 0: poly(0) + poly(1) - claim == 0
	consistencyCheck0 := api.Sub(api.Add(api.Add(circuit.X_11, api.Mul(circuit.X_12, 0)), api.Add(circuit.X_11, api.Mul(circuit.X_12, 1))), api.Add(api.Add(api.Add(circuit.X_7, api.Mul(circuit.X_8, circuit.X_6)), api.Mul(circuit.X_9, api.Mul(circuit.X_6, circuit.X_6))), api.Mul(circuit.X_10, api.Mul(api.Mul(circuit.X_6, circuit.X_6), circuit.X_6))))
	api.AssertIsEqual(consistencyCheck0, 0)

	// Sumcheck round 1: poly(0) + poly(1) - claim == 0
	consistencyCheck1 := api.Sub(api.Add(api.Add(circuit.X_13, api.Mul(circuit.X_14, 0)), api.Add(circuit.X_13, api.Mul(circuit.X_14, 1))), api.Add(circuit.X_11, api.Mul(circuit.X_12, circuit.X_3)))
	api.AssertIsEqual(consistencyCheck1, 0)

	// Sumcheck round 2: poly(0) + poly(1) - claim == 0
	consistencyCheck2 := api.Sub(api.Add(api.Add(circuit.X_15, api.Mul(circuit.X_16, 0)), api.Add(circuit.X_15, api.Mul(circuit.X_16, 1))), api.Add(circuit.X_13, api.Mul(circuit.X_14, circuit.X_4)))
	api.AssertIsEqual(consistencyCheck2, 0)

	// Final claim must match expected
	finalClaim := api.Add(circuit.X_15, api.Mul(circuit.X_16, circuit.X_5))
	api.AssertIsEqual(finalClaim, circuit.ExpectedFinalClaim)

	return nil
}
