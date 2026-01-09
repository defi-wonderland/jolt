package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	jolt "jolt_verifier"
)

const defaultDataPath = "../data/fib_stage1_data.json"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <command> [data_path]")
		fmt.Println("Commands:")
		fmt.Println("  compile  - Compile circuit to R1CS")
		fmt.Println("  setup    - Run Groth16 trusted setup")
		fmt.Println("  prove    - Generate Groth16 proof (requires pk and data)")
		fmt.Println("  verify   - Verify Groth16 proof (requires vk and proof)")
		fmt.Println("  all      - Run full workflow: compile -> setup -> prove -> verify")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "compile":
		compile()
	case "setup":
		setup()
	case "prove":
		dataPath := defaultDataPath
		if len(os.Args) > 2 {
			dataPath = os.Args[2]
		}
		prove(dataPath)
	case "verify":
		verify()
	case "all":
		dataPath := defaultDataPath
		if len(os.Args) > 2 {
			dataPath = os.Args[2]
		}
		runAll(dataPath)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func compile() {
	fmt.Println("=== Compiling Stage1Circuit to R1CS ===")

	var circuit jolt.Stage1Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("R1CS Constraints: %d\n", cs.GetNbConstraints())
	fmt.Printf("Public inputs: %d\n", cs.GetNbPublicVariables())
	fmt.Printf("Secret inputs: %d\n", cs.GetNbSecretVariables())

	// Write R1CS to file
	r1csFile, err := os.Create("stage1.r1cs")
	if err != nil {
		fmt.Printf("Error creating r1cs file: %v\n", err)
		os.Exit(1)
	}
	defer r1csFile.Close()

	_, err = cs.WriteTo(r1csFile)
	if err != nil {
		fmt.Printf("Error writing r1cs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("R1CS written to stage1.r1cs")
}

func setup() {
	fmt.Println("=== Groth16 Trusted Setup ===")

	// Compile fresh (easier than loading)
	var circuit jolt.Stage1Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("R1CS: %d constraints\n", cs.GetNbConstraints())
	fmt.Println("Running Groth16 setup...")

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("Setup error: %v\n", err)
		os.Exit(1)
	}

	// Write proving key
	pkFile, err := os.Create("stage1.pk")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer pkFile.Close()
	pk.WriteTo(pkFile)
	fmt.Println("Proving key written to stage1.pk")

	// Write verification key
	vkFile, err := os.Create("stage1.vk")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer vkFile.Close()
	vk.WriteTo(vkFile)
	fmt.Println("Verification key written to stage1.vk")
}

func prove(dataPath string) {
	fmt.Println("=== Generating Groth16 Proof ===")

	// Load witness data from JSON
	fmt.Printf("Loading witness data from: %s\n", dataPath)
	data, err := jolt.LoadStage1Data(dataPath)
	if err != nil {
		fmt.Printf("Error loading data: %v\n", err)
		os.Exit(1)
	}

	// Create witness
	witnessCircuit, err := jolt.CreateWitness(data)
	if err != nil {
		fmt.Printf("Error creating witness: %v\n", err)
		os.Exit(1)
	}

	// Create full witness
	fullWitness, err := frontend.NewWitness(witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error creating full witness: %v\n", err)
		os.Exit(1)
	}

	// Load proving key
	fmt.Println("Loading proving key...")
	pkFile, err := os.Open("stage1.pk")
	if err != nil {
		fmt.Printf("Error opening pk file: %v\n", err)
		os.Exit(1)
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		fmt.Printf("Error reading pk: %v\n", err)
		os.Exit(1)
	}

	// Load R1CS (needed for proving)
	fmt.Println("Compiling circuit...")
	var circuit jolt.Stage1Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile error: %v\n", err)
		os.Exit(1)
	}

	// Generate proof
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		fmt.Printf("Proving error: %v\n", err)
		os.Exit(1)
	}

	// Write proof
	proofFile, err := os.Create("stage1.proof")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer proofFile.Close()
	proof.WriteTo(proofFile)
	fmt.Println("Proof written to stage1.proof")

	// Also save public witness for verification
	publicWitness, err := fullWitness.Public()
	if err != nil {
		fmt.Printf("Error extracting public witness: %v\n", err)
		os.Exit(1)
	}

	pubFile, err := os.Create("stage1.pub")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer pubFile.Close()
	publicWitness.WriteTo(pubFile)
	fmt.Println("Public witness written to stage1.pub")
}

func verify() {
	fmt.Println("=== Verifying Groth16 Proof ===")

	// Load verification key
	fmt.Println("Loading verification key...")
	vkFile, err := os.Open("stage1.vk")
	if err != nil {
		fmt.Printf("Error opening vk file: %v\n", err)
		os.Exit(1)
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		fmt.Printf("Error reading vk: %v\n", err)
		os.Exit(1)
	}

	// Load proof
	fmt.Println("Loading proof...")
	proofFile, err := os.Open("stage1.proof")
	if err != nil {
		fmt.Printf("Error opening proof file: %v\n", err)
		os.Exit(1)
	}
	defer proofFile.Close()

	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(proofFile)
	if err != nil {
		fmt.Printf("Error reading proof: %v\n", err)
		os.Exit(1)
	}

	// Load public witness
	fmt.Println("Loading public witness...")
	pubFile, err := os.Open("stage1.pub")
	if err != nil {
		fmt.Printf("Error opening public witness file: %v\n", err)
		os.Exit(1)
	}
	defer pubFile.Close()

	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error creating witness: %v\n", err)
		os.Exit(1)
	}
	_, err = publicWitness.ReadFrom(pubFile)
	if err != nil {
		fmt.Printf("Error reading public witness: %v\n", err)
		os.Exit(1)
	}

	// Verify
	fmt.Println("Verifying...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Verification PASSED!")
}

func runAll(dataPath string) {
	fmt.Println("=== Running Full Groth16 Workflow ===\n")

	compile()
	fmt.Println()

	setup()
	fmt.Println()

	prove(dataPath)
	fmt.Println()

	verify()
}
