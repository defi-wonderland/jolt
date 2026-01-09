package jolt_verifier

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
)

// Stage1Data mirrors the Rust ExtractedStage1Data struct
type Stage1Data struct {
	Preamble            *PreambleData  `json:"preamble"`
	UniSkipPolyCoeffs   []string       `json:"uni_skip_poly_coeffs"`
	SumcheckRoundPolys  [][]string     `json:"sumcheck_round_polys"`
	NumRounds           int            `json:"num_rounds"`
	TraceLength         int            `json:"trace_length"`
	Commitments         [][]byte       `json:"commitments"`
	NumCommitments      int            `json:"num_commitments"`
	ExpectedFinalClaim  string         `json:"expected_final_claim"`
}

type PreambleData struct {
	MaxInputSize  uint64 `json:"max_input_size"`
	MaxOutputSize uint64 `json:"max_output_size"`
	MemorySize    uint64 `json:"memory_size"`
	Inputs        []byte `json:"inputs"`
	Outputs       []byte `json:"outputs"`
	Panic         bool   `json:"panic"`
	RamK          uint64 `json:"ram_k"`
	TraceLength   uint64 `json:"trace_length"`
}

// LoadStage1Data loads the extracted Stage 1 data from JSON file
func LoadStage1Data(path string) (*Stage1Data, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var stage1 Stage1Data
	if err := json.Unmarshal(data, &stage1); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &stage1, nil
}

// bytesToFieldElement converts bytes (little-endian) to a big.Int field element
func bytesToFieldElement(bytes []byte) *big.Int {
	// Reverse for big-endian (big.Int expects big-endian)
	reversed := make([]byte, len(bytes))
	for i := 0; i < len(bytes); i++ {
		reversed[i] = bytes[len(bytes)-1-i]
	}
	return new(big.Int).SetBytes(reversed)
}

// padTo32Bytes pads a byte slice to 32 bytes
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded, b)
	return padded
}

// CreateWitness creates a Stage1Circuit with all values populated from extracted data
func CreateWitness(data *Stage1Data) (*Stage1Circuit, error) {
	circuit := &Stage1Circuit{}

	// Use reflection to set fields dynamically
	v := reflect.ValueOf(circuit).Elem()

	// 1. Preamble fields
	if data.Preamble != nil {
		setField(v, "PreambleMaxInputSize", new(big.Int).SetUint64(data.Preamble.MaxInputSize))
		setField(v, "PreambleMaxOutputSize", new(big.Int).SetUint64(data.Preamble.MaxOutputSize))
		setField(v, "PreambleMemorySize", new(big.Int).SetUint64(data.Preamble.MemorySize))

		// Input chunks (only 1 chunk for small inputs)
		inputChunks := chunkBytes(data.Preamble.Inputs, 32)
		for i := 0; i < len(inputChunks) && i < 1; i++ {
			fieldName := fmt.Sprintf("PreambleInputChunk%d", i)
			setField(v, fieldName, bytesToFieldElement(padTo32Bytes(inputChunks[i])))
		}

		// Output chunks (only 1 chunk for small outputs)
		outputChunks := chunkBytes(data.Preamble.Outputs, 32)
		for i := 0; i < len(outputChunks) && i < 1; i++ {
			fieldName := fmt.Sprintf("PreambleOutputChunk%d", i)
			setField(v, fieldName, bytesToFieldElement(padTo32Bytes(outputChunks[i])))
		}

		panicVal := big.NewInt(0)
		if data.Preamble.Panic {
			panicVal = big.NewInt(1)
		}
		setField(v, "PreamblePanic", panicVal)
		setField(v, "PreambleRamK", new(big.Int).SetUint64(data.Preamble.RamK))
		setField(v, "PreambleTraceLength", new(big.Int).SetUint64(data.Preamble.TraceLength))
	}

	// 2. Commitment fields (41 commitments × 12 chunks each)
	for c := 0; c < len(data.Commitments) && c < 41; c++ {
		chunks := chunkBytes(data.Commitments[c], 32)
		for chunk := 0; chunk < len(chunks) && chunk < 12; chunk++ {
			fieldName := fmt.Sprintf("Commitment%dChunk%d", c, chunk)
			setField(v, fieldName, bytesToFieldElement(padTo32Bytes(chunks[chunk])))
		}
	}

	// 3. Uni-skip coefficients (28 coefficients)
	for i := 0; i < len(data.UniSkipPolyCoeffs) && i < 28; i++ {
		fieldName := fmt.Sprintf("UniSkipCoeff%d", i)
		val, ok := new(big.Int).SetString(data.UniSkipPolyCoeffs[i], 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse uni_skip_coeff[%d]: %s", i, data.UniSkipPolyCoeffs[i])
		}
		setField(v, fieldName, val)
	}

	// 4. Sumcheck round polynomials (11 rounds × 3 coefficients each)
	for round := 0; round < len(data.SumcheckRoundPolys) && round < 11; round++ {
		coeffs := data.SumcheckRoundPolys[round]
		for c := 0; c < len(coeffs) && c < 3; c++ {
			fieldName := fmt.Sprintf("SumcheckR%dC%d", round, c)
			val, ok := new(big.Int).SetString(coeffs[c], 10)
			if !ok {
				return nil, fmt.Errorf("failed to parse sumcheck[%d][%d]: %s", round, c, coeffs[c])
			}
			setField(v, fieldName, val)
		}
	}

	// 5. Expected final claim
	finalClaim, ok := new(big.Int).SetString(data.ExpectedFinalClaim, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse expected_final_claim: %s", data.ExpectedFinalClaim)
	}
	setField(v, "ExpectedFinalClaim", finalClaim)

	return circuit, nil
}

// setField sets a field by name using reflection
func setField(v reflect.Value, name string, value *big.Int) {
	field := v.FieldByName(name)
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(value))
	}
}

// chunkBytes splits a byte slice into chunks of the given size
func chunkBytes(b []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(b); i += chunkSize {
		end := i + chunkSize
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[i:end])
	}
	if len(chunks) == 0 {
		// Return at least one empty chunk
		chunks = append(chunks, make([]byte, 0))
	}
	return chunks
}
