// ZK Fiat-Shamir: derives stage challenges from BN254 G1 compressed commitments.
//
// In ZK mode, stages 1-7 hash Pedersen commitments into the Poseidon transcript
// instead of polynomial coefficients. Each commitment is absorbed as its compressed
// BN254 G1 serialization interpreted as Fr (cfr), matching PoseidonTranscript::append_commitment.
//
// The derived challenges flow into the BlindFold verifier as BakedPublicInputs.
package jolt_verifier

import (
	"github.com/consensys/gnark/frontend"
	"jolt_verifier/poseidon"
)

// ZKFiatShamirConfig describes the ZK stage layout for challenge derivation.
// Loaded from the transpiler's output (or hardcoded for a specific program).
type ZKFiatShamirConfig struct {
	// Stages describes each sumcheck stage's structure
	Stages []ZKStageConfig `json:"stages"`

	// JoltTranscriptLabel is the initial transcript label (pre-computed Fr constant)
	// Used when InitialState is nil (synthetic mode — fresh transcript).
	JoltTranscriptLabel *frontend.Variable `json:"-"`

	// SumcheckCommitmentLabel is the pre-computed Fr for "sumcheck_commitment"
	// (used as domain separator before each round commitment absorption)
	SumcheckCommitmentLabel *frontend.Variable `json:"-"`

	// InitialState and InitialNRounds are the transcript state right before stages 1-7.
	// When set (real mode), the transcript starts from this state instead of JoltTranscriptLabel.
	InitialState   *frontend.Variable `json:"-"`
	InitialNRounds *frontend.Variable `json:"-"`
}

// ZKStageConfig describes a single stage for ZK Fiat-Shamir.
type ZKStageConfig struct {
	// NumRounds is the number of sumcheck rounds in this stage
	NumRounds int `json:"num_rounds"`

	// Label is the pre-computed Fr constant for this stage's transcript label
	Label *frontend.Variable `json:"-"`

	// NumCommitmentsPerRound is how many G1 commitments are hashed per round
	// (typically 1 for a single round polynomial commitment)
	NumCommitmentsPerRound int `json:"num_commitments_per_round"`
}

// ZKFiatShamirWitness holds the commitment CFr values for each stage.
type ZKFiatShamirWitness struct {
	// StageCommitmentCFrs[stage][round*commitments_per_round + k] = compressed Fr
	StageCommitmentCFrs [][]frontend.Variable

	// StageCommitmentsX/Y kept for EC folding operations (not transcript)
	StageCommitmentsX [][]frontend.Variable
	StageCommitmentsY [][]frontend.Variable
}

// DeriveZKStageChallenges hashes commitment CFr values into the Poseidon transcript
// and derives all stage challenges.
//
// Matches PoseidonTranscript::append_commitment per round:
//   1. AppendScalar(sumcheckCommitmentLabel)  — domain separator
//   2. AppendScalar(cfr)                       — compressed BN254 G1 as Fr
//   3. ChallengeScalar()                       — derive challenge
//
// Returns: (challenges []frontend.Variable, transcript *poseidon.FrTranscript)
func DeriveZKStageChallenges(
	api frontend.API,
	config *ZKFiatShamirConfig,
	witness *ZKFiatShamirWitness,
) ([]frontend.Variable, *poseidon.FrTranscript) {
	// Initialize transcript: either from pre-computed state (real mode) or fresh label (synthetic)
	var transcript *poseidon.FrTranscript
	if config.InitialState != nil && config.InitialNRounds != nil {
		transcript = poseidon.NewFrTranscriptFromState(api, *config.InitialState, *config.InitialNRounds)
	} else {
		transcript = poseidon.NewFrTranscript(api, *config.JoltTranscriptLabel)
	}

	var allChallenges []frontend.Variable

	for stageIdx, stage := range config.Stages {
		// Append stage label
		if stage.Label != nil {
			transcript.AppendScalar(*stage.Label)
		}

		// For each round: absorb commitment(s) via append_commitment protocol, derive challenge
		for round := 0; round < stage.NumRounds; round++ {
			for k := 0; k < stage.NumCommitmentsPerRound; k++ {
				idx := round*stage.NumCommitmentsPerRound + k
				// Domain separator: raw_append_label("sumcheck_commitment")
				transcript.AppendScalar(*config.SumcheckCommitmentLabel)
				// Commitment absorption: raw_append_bytes(compressed_32) = AppendScalar(cfr)
				transcript.AppendScalar(witness.StageCommitmentCFrs[stageIdx][idx])
			}

			// Derive challenge for this round
			challenge := transcript.ChallengeScalar()
			allChallenges = append(allChallenges, challenge)
		}
	}

	return allChallenges, transcript
}
