package jolt_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

type Stage1Circuit struct {
	UniSkipCoeff0 frontend.Variable `gnark:",public"`
	UniSkipCoeff1 frontend.Variable `gnark:",public"`
	UniSkipCoeff2 frontend.Variable `gnark:",public"`
	UniSkipCoeff3 frontend.Variable `gnark:",public"`
	UniSkipCoeff4 frontend.Variable `gnark:",public"`
	UniSkipCoeff5 frontend.Variable `gnark:",public"`
	UniSkipCoeff6 frontend.Variable `gnark:",public"`
	UniSkipCoeff7 frontend.Variable `gnark:",public"`
	UniSkipCoeff8 frontend.Variable `gnark:",public"`
	UniSkipCoeff9 frontend.Variable `gnark:",public"`
	UniSkipCoeff10 frontend.Variable `gnark:",public"`
	UniSkipCoeff11 frontend.Variable `gnark:",public"`
	UniSkipCoeff12 frontend.Variable `gnark:",public"`
	UniSkipCoeff13 frontend.Variable `gnark:",public"`
	UniSkipCoeff14 frontend.Variable `gnark:",public"`
	UniSkipCoeff15 frontend.Variable `gnark:",public"`
	UniSkipCoeff16 frontend.Variable `gnark:",public"`
	UniSkipCoeff17 frontend.Variable `gnark:",public"`
	UniSkipCoeff18 frontend.Variable `gnark:",public"`
	UniSkipCoeff19 frontend.Variable `gnark:",public"`
	UniSkipCoeff20 frontend.Variable `gnark:",public"`
	UniSkipCoeff21 frontend.Variable `gnark:",public"`
	UniSkipCoeff22 frontend.Variable `gnark:",public"`
	UniSkipCoeff23 frontend.Variable `gnark:",public"`
	UniSkipCoeff24 frontend.Variable `gnark:",public"`
	UniSkipCoeff25 frontend.Variable `gnark:",public"`
	UniSkipCoeff26 frontend.Variable `gnark:",public"`
	UniSkipCoeff27 frontend.Variable `gnark:",public"`
	SumcheckR0C0 frontend.Variable `gnark:",public"`
	SumcheckR0C1 frontend.Variable `gnark:",public"`
	SumcheckR0C2 frontend.Variable `gnark:",public"`
	SumcheckR1C0 frontend.Variable `gnark:",public"`
	SumcheckR1C1 frontend.Variable `gnark:",public"`
	SumcheckR1C2 frontend.Variable `gnark:",public"`
	SumcheckR2C0 frontend.Variable `gnark:",public"`
	SumcheckR2C1 frontend.Variable `gnark:",public"`
	SumcheckR2C2 frontend.Variable `gnark:",public"`
	SumcheckR3C0 frontend.Variable `gnark:",public"`
	SumcheckR3C1 frontend.Variable `gnark:",public"`
	SumcheckR3C2 frontend.Variable `gnark:",public"`
	SumcheckR4C0 frontend.Variable `gnark:",public"`
	SumcheckR4C1 frontend.Variable `gnark:",public"`
	SumcheckR4C2 frontend.Variable `gnark:",public"`
	SumcheckR5C0 frontend.Variable `gnark:",public"`
	SumcheckR5C1 frontend.Variable `gnark:",public"`
	SumcheckR5C2 frontend.Variable `gnark:",public"`
	SumcheckR6C0 frontend.Variable `gnark:",public"`
	SumcheckR6C1 frontend.Variable `gnark:",public"`
	SumcheckR6C2 frontend.Variable `gnark:",public"`
	SumcheckR7C0 frontend.Variable `gnark:",public"`
	SumcheckR7C1 frontend.Variable `gnark:",public"`
	SumcheckR7C2 frontend.Variable `gnark:",public"`
	SumcheckR8C0 frontend.Variable `gnark:",public"`
	SumcheckR8C1 frontend.Variable `gnark:",public"`
	SumcheckR8C2 frontend.Variable `gnark:",public"`
	SumcheckR9C0 frontend.Variable `gnark:",public"`
	SumcheckR9C1 frontend.Variable `gnark:",public"`
	SumcheckR9C2 frontend.Variable `gnark:",public"`
	SumcheckR10C0 frontend.Variable `gnark:",public"`
	SumcheckR10C1 frontend.Variable `gnark:",public"`
	SumcheckR10C2 frontend.Variable `gnark:",public"`
	SumcheckR11C0 frontend.Variable `gnark:",public"`
	SumcheckR11C1 frontend.Variable `gnark:",public"`
	SumcheckR11C2 frontend.Variable `gnark:",public"`
	ExpectedFinalClaim frontend.Variable `gnark:",public"`
}

func (circuit *Stage1Circuit) Define(api frontend.API) error {
	// Memoized subexpressions
	cse_0 := poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, poseidon.Hash(api, 1953263466, 0, 0), 0, 0), 1, 0), 2, 0), 3, 0), 4, 0), 5, 0), 6, 0), 7, 0), 8, 0), 9, 0), 10, 0), 11, 0), 12, 0)
	cse_1 := api.Mul(cse_0, cse_0)
	cse_2 := api.Mul(cse_1, cse_0)
	cse_3 := api.Mul(cse_2, cse_0)
	cse_4 := api.Mul(cse_3, cse_0)
	cse_5 := api.Mul(cse_4, cse_0)
	cse_6 := api.Mul(cse_5, cse_0)
	cse_7 := api.Mul(cse_6, cse_0)
	cse_8 := api.Mul(cse_7, cse_0)
	cse_9 := api.Mul(cse_8, cse_0)
	cse_10 := api.Mul(cse_9, cse_0)
	cse_11 := api.Mul(cse_10, cse_0)
	cse_12 := api.Mul(cse_11, cse_0)
	cse_13 := api.Mul(cse_12, cse_0)
	cse_14 := api.Mul(cse_13, cse_0)
	cse_15 := api.Mul(cse_14, cse_0)
	cse_16 := api.Mul(cse_15, cse_0)
	cse_17 := api.Mul(cse_16, cse_0)
	cse_18 := api.Mul(cse_17, cse_0)
	cse_19 := api.Mul(cse_18, cse_0)
	cse_20 := api.Mul(cse_19, cse_0)
	cse_21 := api.Mul(cse_20, cse_0)
	cse_22 := api.Mul(cse_21, cse_0)
	cse_23 := api.Mul(cse_22, cse_0)
	cse_24 := api.Mul(cse_23, cse_0)
	cse_25 := api.Mul(cse_24, cse_0)
	cse_26 := poseidon.Hash(api, cse_0, 13, 0)
	cse_27 := poseidon.Hash(api, cse_26, 14, 0)
	cse_28 := poseidon.Hash(api, cse_27, 15, 0)
	cse_29 := poseidon.Hash(api, cse_28, 16, 0)
	cse_30 := poseidon.Hash(api, cse_29, 17, 0)
	cse_31 := poseidon.Hash(api, cse_30, 18, 0)
	cse_32 := poseidon.Hash(api, cse_31, 19, 0)
	cse_33 := poseidon.Hash(api, cse_32, 20, 0)
	cse_34 := poseidon.Hash(api, cse_33, 21, 0)
	cse_35 := poseidon.Hash(api, cse_34, 22, 0)
	cse_36 := poseidon.Hash(api, cse_35, 23, 0)
	cse_37 := poseidon.Hash(api, cse_36, 24, 0)

	// power_sum_check
	PowerSumCheck := api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(0, api.Mul(circuit.X_0, 10)), api.Mul(circuit.X_1, 5)), api.Mul(circuit.X_2, 85)), api.Mul(circuit.X_3, 125)), api.Mul(circuit.X_4, 1333)), api.Mul(circuit.X_5, 3125)), api.Mul(circuit.X_6, 25405)), api.Mul(circuit.X_7, 78125)), api.Mul(circuit.X_8, 535333)), api.Mul(circuit.X_9, 1953125)), api.Mul(circuit.X_10, 11982925)), api.Mul(circuit.X_11, 48828125)), api.Mul(circuit.X_12, 278766133)), api.Mul(circuit.X_13, 1220703125)), api.Mul(circuit.X_14, 6649985245)), api.Mul(circuit.X_15, 30517578125)), api.Mul(circuit.X_16, 161264049733)), api.Mul(circuit.X_17, 762939453125)), api.Mul(circuit.X_18, 3952911584365)), api.Mul(circuit.X_19, 19073486328125)), api.Mul(circuit.X_20, 97573430562133)), api.Mul(circuit.X_21, 476837158203125)), api.Mul(circuit.X_22, 2419432933612285)), api.Mul(circuit.X_23, 11920928955078125)), api.Mul(circuit.X_24, 60168159621439333)), api.Mul(circuit.X_25, 298023223876953125)), api.Mul(circuit.X_26, 1499128402505381005)), api.Mul(circuit.X_27, 7450580596923828125))
	api.AssertIsEqual(PowerSumCheck, 0)

	// sumcheck_consistency_0
	SumcheckConsistency0 := api.Sub(api.Add(api.Add(api.Add(circuit.X_28, api.Mul(circuit.X_29, 0)), api.Mul(circuit.X_30, api.Mul(0, 0))), api.Add(api.Add(circuit.X_28, api.Mul(circuit.X_29, 1)), api.Mul(circuit.X_30, api.Mul(1, 1)))), api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(api.Add(circuit.X_0, api.Mul(circuit.X_1, cse_0)), api.Mul(circuit.X_2, cse_1)), api.Mul(circuit.X_3, cse_2)), api.Mul(circuit.X_4, cse_3)), api.Mul(circuit.X_5, cse_4)), api.Mul(circuit.X_6, cse_5)), api.Mul(circuit.X_7, cse_6)), api.Mul(circuit.X_8, cse_7)), api.Mul(circuit.X_9, cse_8)), api.Mul(circuit.X_10, cse_9)), api.Mul(circuit.X_11, cse_10)), api.Mul(circuit.X_12, cse_11)), api.Mul(circuit.X_13, cse_12)), api.Mul(circuit.X_14, cse_13)), api.Mul(circuit.X_15, cse_14)), api.Mul(circuit.X_16, cse_15)), api.Mul(circuit.X_17, cse_16)), api.Mul(circuit.X_18, cse_17)), api.Mul(circuit.X_19, cse_18)), api.Mul(circuit.X_20, cse_19)), api.Mul(circuit.X_21, cse_20)), api.Mul(circuit.X_22, cse_21)), api.Mul(circuit.X_23, cse_22)), api.Mul(circuit.X_24, cse_23)), api.Mul(circuit.X_25, cse_24)), api.Mul(circuit.X_26, cse_25)), api.Mul(circuit.X_27, api.Mul(cse_25, cse_0))))
	api.AssertIsEqual(SumcheckConsistency0, 0)

	// sumcheck_consistency_1
	SumcheckConsistency1 := api.Sub(api.Add(api.Add(api.Add(circuit.X_31, api.Mul(circuit.X_32, 0)), api.Mul(circuit.X_33, api.Mul(0, 0))), api.Add(api.Add(circuit.X_31, api.Mul(circuit.X_32, 1)), api.Mul(circuit.X_33, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_28, api.Mul(circuit.X_29, cse_26)), api.Mul(circuit.X_30, api.Mul(cse_26, cse_26))))
	api.AssertIsEqual(SumcheckConsistency1, 0)

	// sumcheck_consistency_2
	SumcheckConsistency2 := api.Sub(api.Add(api.Add(api.Add(circuit.X_34, api.Mul(circuit.X_35, 0)), api.Mul(circuit.X_36, api.Mul(0, 0))), api.Add(api.Add(circuit.X_34, api.Mul(circuit.X_35, 1)), api.Mul(circuit.X_36, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_31, api.Mul(circuit.X_32, cse_27)), api.Mul(circuit.X_33, api.Mul(cse_27, cse_27))))
	api.AssertIsEqual(SumcheckConsistency2, 0)

	// sumcheck_consistency_3
	SumcheckConsistency3 := api.Sub(api.Add(api.Add(api.Add(circuit.X_37, api.Mul(circuit.X_38, 0)), api.Mul(circuit.X_39, api.Mul(0, 0))), api.Add(api.Add(circuit.X_37, api.Mul(circuit.X_38, 1)), api.Mul(circuit.X_39, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_34, api.Mul(circuit.X_35, cse_28)), api.Mul(circuit.X_36, api.Mul(cse_28, cse_28))))
	api.AssertIsEqual(SumcheckConsistency3, 0)

	// sumcheck_consistency_4
	SumcheckConsistency4 := api.Sub(api.Add(api.Add(api.Add(circuit.X_40, api.Mul(circuit.X_41, 0)), api.Mul(circuit.X_42, api.Mul(0, 0))), api.Add(api.Add(circuit.X_40, api.Mul(circuit.X_41, 1)), api.Mul(circuit.X_42, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_37, api.Mul(circuit.X_38, cse_29)), api.Mul(circuit.X_39, api.Mul(cse_29, cse_29))))
	api.AssertIsEqual(SumcheckConsistency4, 0)

	// sumcheck_consistency_5
	SumcheckConsistency5 := api.Sub(api.Add(api.Add(api.Add(circuit.X_43, api.Mul(circuit.X_44, 0)), api.Mul(circuit.X_45, api.Mul(0, 0))), api.Add(api.Add(circuit.X_43, api.Mul(circuit.X_44, 1)), api.Mul(circuit.X_45, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_40, api.Mul(circuit.X_41, cse_30)), api.Mul(circuit.X_42, api.Mul(cse_30, cse_30))))
	api.AssertIsEqual(SumcheckConsistency5, 0)

	// sumcheck_consistency_6
	SumcheckConsistency6 := api.Sub(api.Add(api.Add(api.Add(circuit.X_46, api.Mul(circuit.X_47, 0)), api.Mul(circuit.X_48, api.Mul(0, 0))), api.Add(api.Add(circuit.X_46, api.Mul(circuit.X_47, 1)), api.Mul(circuit.X_48, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_43, api.Mul(circuit.X_44, cse_31)), api.Mul(circuit.X_45, api.Mul(cse_31, cse_31))))
	api.AssertIsEqual(SumcheckConsistency6, 0)

	// sumcheck_consistency_7
	SumcheckConsistency7 := api.Sub(api.Add(api.Add(api.Add(circuit.X_49, api.Mul(circuit.X_50, 0)), api.Mul(circuit.X_51, api.Mul(0, 0))), api.Add(api.Add(circuit.X_49, api.Mul(circuit.X_50, 1)), api.Mul(circuit.X_51, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_46, api.Mul(circuit.X_47, cse_32)), api.Mul(circuit.X_48, api.Mul(cse_32, cse_32))))
	api.AssertIsEqual(SumcheckConsistency7, 0)

	// sumcheck_consistency_8
	SumcheckConsistency8 := api.Sub(api.Add(api.Add(api.Add(circuit.X_52, api.Mul(circuit.X_53, 0)), api.Mul(circuit.X_54, api.Mul(0, 0))), api.Add(api.Add(circuit.X_52, api.Mul(circuit.X_53, 1)), api.Mul(circuit.X_54, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_49, api.Mul(circuit.X_50, cse_33)), api.Mul(circuit.X_51, api.Mul(cse_33, cse_33))))
	api.AssertIsEqual(SumcheckConsistency8, 0)

	// sumcheck_consistency_9
	SumcheckConsistency9 := api.Sub(api.Add(api.Add(api.Add(circuit.X_55, api.Mul(circuit.X_56, 0)), api.Mul(circuit.X_57, api.Mul(0, 0))), api.Add(api.Add(circuit.X_55, api.Mul(circuit.X_56, 1)), api.Mul(circuit.X_57, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_52, api.Mul(circuit.X_53, cse_34)), api.Mul(circuit.X_54, api.Mul(cse_34, cse_34))))
	api.AssertIsEqual(SumcheckConsistency9, 0)

	// sumcheck_consistency_10
	SumcheckConsistency10 := api.Sub(api.Add(api.Add(api.Add(circuit.X_58, api.Mul(circuit.X_59, 0)), api.Mul(circuit.X_60, api.Mul(0, 0))), api.Add(api.Add(circuit.X_58, api.Mul(circuit.X_59, 1)), api.Mul(circuit.X_60, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_55, api.Mul(circuit.X_56, cse_35)), api.Mul(circuit.X_57, api.Mul(cse_35, cse_35))))
	api.AssertIsEqual(SumcheckConsistency10, 0)

	// sumcheck_consistency_11
	SumcheckConsistency11 := api.Sub(api.Add(api.Add(api.Add(circuit.X_61, api.Mul(circuit.X_62, 0)), api.Mul(circuit.X_63, api.Mul(0, 0))), api.Add(api.Add(circuit.X_61, api.Mul(circuit.X_62, 1)), api.Mul(circuit.X_63, api.Mul(1, 1)))), api.Add(api.Add(circuit.X_58, api.Mul(circuit.X_59, cse_36)), api.Mul(circuit.X_60, api.Mul(cse_36, cse_36))))
	api.AssertIsEqual(SumcheckConsistency11, 0)

	// final_claim
	FinalClaim := api.Add(api.Add(circuit.X_61, api.Mul(circuit.X_62, cse_37)), api.Mul(circuit.X_63, api.Mul(cse_37, cse_37)))
	api.AssertIsEqual(FinalClaim, circuit.ExpectedFinalClaim)

	return nil
}
