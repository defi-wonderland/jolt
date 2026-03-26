// Combined ZK circuit: ZK Fiat-Shamir + BlindFold verifier in a single Groth16 circuit.
//
// Part 1 (ZK Fiat-Shamir): Hashes Grumpkin G1 commitment coordinates into Poseidon
// transcript, derives all stage challenges. No equality assertions.
//
// Part 2 (BlindFold): Verifies the BlindFold proof (Nova folding + Spartan sumchecks)
// using the stage challenges from Part 1.
//
// Total: ~148K constraints (without PCS).
package jolt_verifier

import (
	"github.com/consensys/gnark/frontend"
)

// ZKVerifierCircuit is the top-level Groth16 circuit for ZK Jolt verification.
type ZKVerifierCircuit struct {
	// === Part 1: ZK Fiat-Shamir (derives stage challenges from G1 commitments) ===
	FiatShamirConfig  ZKFiatShamirConfig  `gnark:"-"`
	FiatShamirWitness ZKFiatShamirWitness

	// === Part 2: BlindFold verifier ===
	BlindFold BlindFoldCircuit
}

// Define implements the gnark circuit interface.
func (c *ZKVerifierCircuit) Define(api frontend.API) error {
	// Part 1: Derive stage challenges from G1 commitments
	challenges, _ := DeriveZKStageChallenges(
		api,
		&c.FiatShamirConfig,
		&c.FiatShamirWitness,
	)

	// Pass derived stage challenges to BlindFold.
	// BlindFold.Define() will assert these match the baked challenge values
	// that were used to build the R1CS matrices, proving the R1CS was built
	// from correctly derived Fiat-Shamir challenges.
	c.BlindFold.StageChallenges = challenges

	// Part 2: Verify BlindFold proof
	return c.BlindFold.Define(api)
}
