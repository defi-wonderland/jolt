//! Poseidon hash support for MleAst
//!
//! Extends the AST with Poseidon hash operations for circuit-friendly
//! Fiat-Shamir transcript construction.

use zklean_extractor::mle_ast::MleAst;

/// Poseidon hash operation for MleAst
///
/// Takes a variable number of field elements and produces a single hash output.
/// This is recorded as an AST node during symbolic execution and later transpiled
/// to Gnark's native Poseidon implementation.
pub trait PoseidonHash: Sized {
    /// Hash multiple field elements using Poseidon
    ///
    /// # Arguments
    /// * `inputs` - Slice of field elements to hash
    ///
    /// # Returns
    /// Single field element representing the hash output
    fn poseidon_hash(inputs: &[Self]) -> Self;
}

impl PoseidonHash for MleAst {
    fn poseidon_hash(inputs: &[Self]) -> Self {
        match inputs.len() {
            0 => panic!("Cannot hash empty input"),
            1 => inputs[0].clone(),
            2 => MleAst::poseidon2(&inputs[0], &inputs[1]),
            3 => {
                // Hash first two, then hash result with third
                let h1 = MleAst::poseidon2(&inputs[0], &inputs[1]);
                MleAst::poseidon2(&h1, &inputs[2])
            }
            4 => MleAst::poseidon4(&inputs[0], &inputs[1], &inputs[2], &inputs[3]),
            _ => {
                // For longer inputs, chunk into groups of 4
                let mut state = MleAst::poseidon4(&inputs[0], &inputs[1], &inputs[2], &inputs[3]);
                let mut i = 4;
                while i < inputs.len() {
                    let remaining = inputs.len() - i;
                    if remaining >= 4 {
                        state = MleAst::poseidon4(&state, &inputs[i], &inputs[i + 1], &inputs[i + 2]);
                        i += 3; // Absorb 3 new elements (1 is the state)
                    } else if remaining == 3 {
                        state = MleAst::poseidon4(&state, &inputs[i], &inputs[i + 1], &inputs[i + 2]);
                        i += 3;
                    } else if remaining == 2 {
                        let h = MleAst::poseidon2(&inputs[i], &inputs[i + 1]);
                        state = MleAst::poseidon2(&state, &h);
                        i += 2;
                    } else {
                        state = MleAst::poseidon2(&state, &inputs[i]);
                        i += 1;
                    }
                }
                state
            }
        }
    }
}

/// Fiat-Shamir transcript using Poseidon hash
///
/// Provides a transcript protocol compatible with symbolic execution.
/// When used with MleAst, operations are recorded to the AST instead of computed.
pub struct PoseidonTranscript<F> {
    /// Current state of the transcript (absorbed elements)
    state: Vec<F>,
}

impl<F> PoseidonTranscript<F> {
    /// Create a new empty transcript
    pub fn new() -> Self {
        Self { state: Vec::new() }
    }
}

impl<F: Clone> PoseidonTranscript<F>
where
    F: PoseidonHash,
{
    /// Append a field element to the transcript
    pub fn append_field(&mut self, element: F) {
        self.state.push(element);
    }

    /// Derive a challenge from the current transcript state
    ///
    /// This squeezes a challenge value from the absorbed elements.
    /// For MleAst, this creates a Poseidon hash node in the AST.
    pub fn challenge(&mut self) -> F {
        let challenge = F::poseidon_hash(&self.state);
        // Update state with challenge for domain separation
        self.state.push(challenge.clone());
        challenge
    }
}

// Implement the trait from jolt-core for compatibility
impl<F> jolt_core::zkvm::stage1_only_verifier::PoseidonTranscriptProtocol for PoseidonTranscript<F>
where
    F: jolt_core::field::JoltField + PoseidonHash + Clone,
{
    type Challenge = F;

    fn append_field(&mut self, element: Self::Challenge) {
        self.append_field(element);
    }

    fn challenge(&mut self) -> Self::Challenge {
        self.challenge()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_creation() {
        let transcript: PoseidonTranscript<MleAst> = PoseidonTranscript::new();
        assert_eq!(transcript.state.len(), 0);
    }
}
