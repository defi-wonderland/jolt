package jolt_verifier

import (
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
)

// BlindFoldConfig holds the program-specific dimensions and R1CS matrices.
// Loaded from blindfold_config.json (exported by Rust transpiler).
// These are CONSTANTS for a given proof — the circuit is compiled with them fixed.
type BlindFoldConfig struct {
	// === Dimensions ===
	NumConstraints int `json:"num_constraints"` // R1CS rows (padded to power of 2)
	NumVars        int `json:"num_vars"`        // Spartan rounds = log2(NumConstraints)
	InnerNumVars   int `json:"inner_num_vars"`  // Inner sumcheck rounds = log2(R_prime * C)

	// === Hyrax grid params ===
	C              int `json:"c"`               // Column count (power of 2)
	RCoeff         int `json:"r_coeff"`         // Coefficient rows
	RPrime         int `json:"r_prime"`         // Total W rows (power of 2)
	RE             int `json:"r_e"`             // E grid rows
	CE             int `json:"c_e"`             // E grid columns
	TotalRounds    int `json:"total_rounds"`    // Total sumcheck rounds across all stages
	NoncoeffCount  int `json:"noncoeff_count"`  // Non-coefficient witness variables

	// === Degree bounds ===
	SpartanDegree int `json:"spartan_degree"` // Outer sumcheck degree (typically 3)
	InnerDegree   int `json:"inner_degree"`   // Inner sumcheck degree (typically 2)

	// === Commitment counts (for array sizing) ===
	NumRoundCommitments     int `json:"num_round_commitments"`
	NumNoncoeffCommitments  int `json:"num_noncoeff_commitments"`
	NumERowCommitments      int `json:"num_e_row_commitments"`
	NumEvalCommitments      int `json:"num_eval_commitments"`
	NumCrossTermCommitments int `json:"num_cross_term_commitments"`

	// === Sparse R1CS matrices ===
	// Entries include column-0 values (baked from concrete challenge values).
	// These are constant for a given proof.
	R1CSA []SparseEntryJSON `json:"r1cs_a"`
	R1CSB []SparseEntryJSON `json:"r1cs_b"`
	R1CSC []SparseEntryJSON `json:"r1cs_c"`
}

// SparseEntryJSON is a JSON-serializable sparse matrix entry.
type SparseEntryJSON struct {
	Row   int    `json:"row"`
	Col   int    `json:"col"`
	Coeff string `json:"coeff"` // Hex string for big.Int
}

// SparseEntry is a parsed sparse matrix entry with big.Int coefficient.
type SparseEntry struct {
	Row   int
	Col   int
	Coeff *big.Int
}

// G1PointJSON is a JSON-serializable Grumpkin G1 affine point.
// Coordinates are BN254 Fr elements (native in gnark).
// CFr is the BN254 G1 compressed serialization interpreted as Fr
// (used for Poseidon transcript absorption).
type G1PointJSON struct {
	X   string `json:"x"`   // Hex string for big.Int (Grumpkin X coord)
	Y   string `json:"y"`   // Hex string for big.Int (Grumpkin Y coord)
	CFr string `json:"cfr"` // Hex string: from_le_bytes_mod_order(serialize_compressed(BN254_G1))
}

// BlindFoldWitnessJSON holds the proof-specific witness values.
// Loaded from blindfold_witness.json (exported by Rust transpiler).
type BlindFoldWitnessJSON struct {
	// Random instance
	RandomU          string        `json:"random_u"`
	RandomRoundComs  []G1PointJSON `json:"random_round_coms"`
	RandomNoncoeff   []G1PointJSON `json:"random_noncoeff"`
	RandomERows      []G1PointJSON `json:"random_e_rows"`
	RandomEvalComs   []G1PointJSON `json:"random_eval_coms"`

	// Cross-term commitments
	CrossTermComs []G1PointJSON `json:"cross_term_coms"`

	// Real instance (from stages 1-7 ZK proof)
	RealRoundComs []G1PointJSON `json:"real_round_coms"`
	RealEvalComs  []G1PointJSON `json:"real_eval_coms"`

	// Real noncoeff row commitments (from BlindFold proof, not stages)
	RealNoncoeffComs []G1PointJSON `json:"real_noncoeff_coms"`

	// Spartan outer sumcheck coefficients [num_vars rounds][spartan_degree-1 coeffs]
	SpartanCoeffs [][]string `json:"spartan_coeffs"`
	AzR           string     `json:"az_r"`
	BzR           string     `json:"bz_r"`
	CzR           string     `json:"cz_r"`

	// Inner sumcheck coefficients [inner_num_vars rounds][inner_degree-1 coeffs]
	InnerCoeffs [][]string `json:"inner_coeffs"`

	// Trusted witness (deferred PCS verification)
	ER  string `json:"e_r"`
	WRy string `json:"w_ry"`

	// Folded u scalar (after folding: u_folded = 1 + r * random_u)
	FoldedU string `json:"folded_u"`

	// Pedersen generators
	PedersenG G1PointJSON `json:"pedersen_g"`
	PedersenH G1PointJSON `json:"pedersen_h"`

	// Baked challenge values (stage 1-7 sumcheck round challenges baked into R1CS)
	BakedChallenges []string `json:"baked_challenges"`

	// Debug checkpoints for transcript parity verification
	DebugRChallenge      string   `json:"debug_r_challenge"`
	DebugTau             []string `json:"debug_tau"`
	DebugRx              []string `json:"debug_rx"`
	DebugRa              string   `json:"debug_ra"`
	DebugRb              string   `json:"debug_rb"`
	DebugRc              string   `json:"debug_rc"`
	DebugPubAz           string   `json:"debug_pub_az"`
	DebugPubBz           string   `json:"debug_pub_bz"`
	DebugPubCz           string   `json:"debug_pub_cz"`
	DebugInnerClaimInit  string   `json:"debug_inner_claim_initial"`
	DebugRy              []string `json:"debug_ry"`
	DebugLwAtRy          string   `json:"debug_lw_at_ry"`
	DebugInnerClaimFinal string   `json:"debug_inner_claim_final"`
}

// LoadBlindFoldConfig loads config from a JSON file.
func LoadBlindFoldConfig(path string) (*BlindFoldConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config BlindFoldConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// LoadBlindFoldWitness loads witness from a JSON file.
func LoadBlindFoldWitness(path string) (*BlindFoldWitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var witness BlindFoldWitnessJSON
	if err := json.Unmarshal(data, &witness); err != nil {
		return nil, err
	}
	return &witness, nil
}

// ZKFiatShamirWitnessJSON holds exported ZK Fiat-Shamir test data.
// Loaded from zk_fiat_shamir_witness.json (exported by Rust).
type ZKFiatShamirWitnessJSON struct {
	JoltLabel          string                  `json:"jolt_label"`
	TranscriptState    *string                 `json:"transcript_state,omitempty"`
	TranscriptNRounds  *int                    `json:"transcript_n_rounds,omitempty"`
	Stages             []ZKFiatShamirStageJSON `json:"stages"`
	ExpectedChallenges []string                `json:"expected_challenges"`
}

// ZKFiatShamirStageJSON describes one stage for ZK Fiat-Shamir.
type ZKFiatShamirStageJSON struct {
	Label                   string   `json:"label"`
	NumRounds               int      `json:"num_rounds"`
	NumCommitmentsPerRound  int      `json:"num_commitments_per_round"`
	CommitmentXs            []string `json:"commitment_xs"`
	CommitmentYs            []string `json:"commitment_ys"`
	CommitmentCFrs          []string `json:"commitment_cfrs"`
}

// LoadZKFiatShamirWitness loads ZK Fiat-Shamir test data from a JSON file.
func LoadZKFiatShamirWitness(path string) (*ZKFiatShamirWitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var witness ZKFiatShamirWitnessJSON
	if err := json.Unmarshal(data, &witness); err != nil {
		return nil, err
	}
	return &witness, nil
}

// ParseSparseEntries converts JSON sparse entries to parsed entries with big.Int coefficients.
func ParseSparseEntries(entries []SparseEntryJSON) []SparseEntry {
	result := make([]SparseEntry, len(entries))
	for i, e := range entries {
		coeff := new(big.Int)
		coeff.SetString(e.Coeff, 16)
		result[i] = SparseEntry{
			Row:   e.Row,
			Col:   e.Col,
			Coeff: coeff,
		}
	}
	return result
}

// ParseHexToBigInt parses a hex string to big.Int, returning nil on empty string.
func ParseHexToBigInt(hex string) *big.Int {
	if hex == "" {
		return new(big.Int)
	}
	v := new(big.Int)
	v.SetString(hex, 16)
	return v
}

// ParseG1Point converts a JSON G1 point to frontend.Variable pair.
func ParseG1Point(p G1PointJSON) (frontend.Variable, frontend.Variable) {
	return ParseHexToBigInt(p.X), ParseHexToBigInt(p.Y)
}

// ParseG1Points converts a slice of JSON G1 points to parallel X and Y slices.
func ParseG1Points(points []G1PointJSON) (xs, ys []frontend.Variable) {
	xs = make([]frontend.Variable, len(points))
	ys = make([]frontend.Variable, len(points))
	for i, p := range points {
		xs[i], ys[i] = ParseG1Point(p)
	}
	return
}

// ParseG1PointsCFr extracts the compressed Fr values from a slice of G1 points.
// These are used for Poseidon transcript absorption (1 hash per commitment).
func ParseG1PointsCFr(points []G1PointJSON) []frontend.Variable {
	result := make([]frontend.Variable, len(points))
	for i, p := range points {
		result[i] = ParseHexToBigInt(p.CFr)
	}
	return result
}

// ParseScalarSlice converts hex strings to frontend.Variable slice.
func ParseScalarSlice(hexes []string) []frontend.Variable {
	result := make([]frontend.Variable, len(hexes))
	for i, h := range hexes {
		result[i] = ParseHexToBigInt(h)
	}
	return result
}

// ParseScalarMatrix converts a 2D hex string matrix to 2D frontend.Variable.
func ParseScalarMatrix(hexes [][]string) [][]frontend.Variable {
	result := make([][]frontend.Variable, len(hexes))
	for i, row := range hexes {
		result[i] = ParseScalarSlice(row)
	}
	return result
}

// labelToFr converts a label string to a BN254 Fr element, matching Rust's
// Fr::from_le_bytes_mod_order(label_bytes).
// Interprets the label bytes as a little-endian integer and reduces mod Fr modulus.
func labelToFr(label string) *big.Int {
	bytes := []byte(label)
	// Reverse to big-endian for big.Int.SetBytes
	reversed := make([]byte, len(bytes))
	for i, b := range bytes {
		reversed[len(bytes)-1-i] = b
	}
	v := new(big.Int).SetBytes(reversed)
	// For short labels (< 32 bytes), the value is always < modulus, but reduce for safety
	frMod, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	v.Mod(v, frMod)
	return v
}

// labelToFrWithLen packs label (right-padded to 24 bytes) + length (8 bytes big-endian)
// into a 32-byte word, then interprets as LE integer mod Fr.
// Matches Rust's PoseidonTranscript::raw_append_label_with_len.
func labelToFrWithLen(label string, length uint64) *big.Int {
	var packed [32]byte
	copy(packed[:], []byte(label)) // Label in first 24 bytes (right-padded with zeros)
	binary.BigEndian.PutUint64(packed[24:], length) // Length in bytes 24-31 (big-endian)

	// Interpret as LE integer for big.Int (which uses BE), so reverse
	reversed := make([]byte, 32)
	for i, b := range packed {
		reversed[31-i] = b
	}
	v := new(big.Int).SetBytes(reversed)
	frMod, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	v.Mod(v, frMod)
	return v
}

// identityCompressedFr returns the Fr value for BN254 G1 identity point's compressed serialization.
// Identity: X=0, flags=PointAtInfinity → byte[31] = 0x40 → LE integer = 2^254.
// (ark-serialize SWFlags::PointAtInfinity = 0x40, not 0x80)
func identityCompressedFr() *big.Int {
	val := new(big.Int).Lsh(big.NewInt(1), 254) // 2^254
	frMod, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	val.Mod(val, frMod)
	return val
}

// initLabels sets all transcript label constants on a BlindFoldCircuit.
// Labels must match the Rust BlindFold protocol's label strings exactly.
func initLabels(c *BlindFoldCircuit) {
	// Plain labels (used with append_label / raw_append_label — no length packing)
	c.LabelBlindFold = labelToFr("BlindFold")
	c.LabelRealInstance = labelToFr("BlindFold_real_instance")
	c.LabelRandomInstance = labelToFr("BlindFold_random_instance")
	c.LabelSpartan = labelToFr("BlindFold_spartan")

	// Packed labels (used with append_bytes / append_scalars / append_commitments
	// — match Rust's raw_append_label_with_len(label, count))
	c.LabelU = labelToFrWithLen("blindfold_u", 32) // append_bytes: u_bytes.len() = 32
	c.LabelRoundComs = labelToFrWithLen("blindfold_round_coms", uint64(c.Config.NumRoundCommitments))
	c.LabelNoncoeff = labelToFrWithLen("blindfold_noncoeff", uint64(c.Config.NumNoncoeffCommitments))
	c.LabelERows = labelToFrWithLen("blindfold_e_rows", uint64(c.Config.NumERowCommitments))
	c.LabelEvalComs = labelToFrWithLen("blindfold_eval_coms", uint64(c.Config.NumEvalCommitments))
	c.LabelCrossTerm = labelToFrWithLen("blindfold_cross_term", uint64(c.Config.NumCrossTermCommitments))
	c.LabelSumcheckPoly = labelToFrWithLen("sumcheck_poly", uint64(c.Config.SpartanDegree))
	c.LabelAzBzCz = labelToFrWithLen("blindfold_az_bz_cz", 3) // always 3 scalars
	c.LabelInnerSumcheckPoly = labelToFrWithLen("inner_sumcheck_poly", uint64(c.Config.InnerDegree))
}
