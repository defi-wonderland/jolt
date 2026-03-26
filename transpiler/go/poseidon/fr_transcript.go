// FrTranscript implements a Fiat-Shamir transcript using native Poseidon over BN254 Fr.
//
// Ported from quangvdao/quang-jolt with AppendG1Point for BlindFold G1 commitment hashing.
// Uses Hash(state, nRounds, data) → new_state for each absorption.
// ~250 constraints per hash (native Poseidon, no emulation).
package poseidon

import (
	"github.com/consensys/gnark/frontend"
)

// FrTranscript is a Fiat-Shamir transcript using native Poseidon over Fr.
type FrTranscript struct {
	api frontend.API

	// state is the running Poseidon hash state (native Fr element)
	state frontend.Variable

	// nRounds counter for domain separation
	nRounds frontend.Variable
}

// NewFrTranscript creates a new native Fr Poseidon transcript with the given label.
func NewFrTranscript(api frontend.API, label frontend.Variable) *FrTranscript {
	// Initial hash: state = hash(label, 0, 0)
	zero := frontend.Variable(0)
	initialState := Hash(api, label, zero, zero)

	return &FrTranscript{
		api:     api,
		state:   initialState,
		nRounds: zero,
	}
}

// NewFrTranscriptFromState creates a transcript with pre-initialized state.
func NewFrTranscriptFromState(
	api frontend.API,
	state frontend.Variable,
	nRounds frontend.Variable,
) *FrTranscript {
	return &FrTranscript{
		api:     api,
		state:   state,
		nRounds: nRounds,
	}
}

// AppendScalar absorbs a native Fr scalar into the transcript.
func (t *FrTranscript) AppendScalar(scalar frontend.Variable) {
	t.state = Hash(t.api, t.state, t.nRounds, scalar)
	t.nRounds = t.api.Add(t.nRounds, 1)
}

// AppendMessage absorbs a constant message (32 bytes) into the transcript.
// The message is interpreted as big-endian bytes converted to a field element.
func (t *FrTranscript) AppendMessage(msgBytes32 [32]byte) {
	msgVar := frontend.Variable(msgBytes32[:])
	t.AppendScalar(msgVar)
}

// AppendG1Point absorbs a Grumpkin G1 point into the transcript by hashing
// both coordinates (X, Y) as native Fr elements.
//
// Grumpkin base field = BN254 scalar field, so G1 point coordinates are native.
// We hash X then Y as two separate scalar absorptions.
//
// NOTE: The Rust-side transcript must be modified to match this hashing scheme.
// The default Rust behavior (serialize_compressed → from_le_bytes_mod_order)
// will NOT match. The Rust export code must hash (X, Y) the same way.
func (t *FrTranscript) AppendG1Point(x, y frontend.Variable) {
	t.AppendScalar(x)
	t.AppendScalar(y)
}

// ChallengeScalar squeezes a challenge from the transcript.
// Returns a native Fr element.
func (t *FrTranscript) ChallengeScalar() frontend.Variable {
	zero := frontend.Variable(0)

	// Hash to get random output
	output := Hash(t.api, t.state, t.nRounds, zero)

	// Update state
	t.state = output
	t.nRounds = t.api.Add(t.nRounds, 1)

	return output
}

// GetState returns the current transcript state.
func (t *FrTranscript) GetState() frontend.Variable {
	return t.state
}

// GetNRounds returns the current round counter.
func (t *FrTranscript) GetNRounds() frontend.Variable {
	return t.nRounds
}
