package elgamal

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// EncryptCircuit defines a circuit that performs ElGamal encryption using the standard Encrypt method
type EncryptCircuit struct {
	PubKey twistededwards.Point
	K      frontend.Variable
	M      frontend.Variable
	Result struct {
		C1 twistededwards.Point
		C2 twistededwards.Point
	} `gnark:",public"`
}

// Define implements the circuit logic for standard Encrypt
func (c *EncryptCircuit) Define(api frontend.API) error {
	// Initialize the twisted Edwards curve for BN254
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return err
	}

	// Get the base point (G)
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}

	// Perform encryption using standard method (3 scalar muls + 1 add)
	// c1 = [k] * G
	c1 := curve.ScalarMul(G, c.K)
	// s = [k] * publicKey
	s := curve.ScalarMul(c.PubKey, c.K)
	// m = [message] * G
	mPoint := curve.ScalarMul(G, c.M)
	// c2 = m + s
	c2 := curve.Add(mPoint, s)

	// Assert results match expected values
	api.AssertIsEqual(c1.X, c.Result.C1.X)
	api.AssertIsEqual(c1.Y, c.Result.C1.Y)
	api.AssertIsEqual(c2.X, c.Result.C2.X)
	api.AssertIsEqual(c2.Y, c.Result.C2.Y)

	return nil
}

// EncryptOptimizedCircuit defines a circuit that performs ElGamal encryption using the optimized Encrypt method
type EncryptOptimizedCircuit struct {
	PubKey twistededwards.Point
	K      frontend.Variable
	M      frontend.Variable
	Result struct {
		C1 twistededwards.Point
		C2 twistededwards.Point
	} `gnark:",public"`
}

// Define implements the circuit logic for optimized Encrypt with fixed-base scalar multiplication
func (c *EncryptOptimizedCircuit) Define(api frontend.API) error {
	var cipher Ciphertext
	encryptedCipher, err := cipher.Encrypt(api, c.PubKey, c.K, c.M)
	if err != nil {
		return err
	}

	// Assert results match expected values
	api.AssertIsEqual(encryptedCipher.C1.X, c.Result.C1.X)
	api.AssertIsEqual(encryptedCipher.C1.Y, c.Result.C1.Y)
	api.AssertIsEqual(encryptedCipher.C2.X, c.Result.C2.X)
	api.AssertIsEqual(encryptedCipher.C2.Y, c.Result.C2.Y)

	return nil
}

func TestEncryptComparison(t *testing.T) {
	fmt.Println("\n=== Constraint Comparison Summary ===")

	// Test standard Encrypt
	circuit1 := &EncryptCircuit{}
	p1 := profile.Start()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit1)
	if err != nil {
		t.Fatalf("Encrypt circuit compilation failed: %v", err)
	}
	p1.Stop()
	encryptConstraints := ccs.GetNbConstraints()

	// Test optimized Encrypt with fixed-base scalar multiplication
	circuit3 := &EncryptOptimizedCircuit{}
	p3 := profile.Start()
	ccs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit3)
	if err != nil {
		t.Fatalf("Encrypt circuit compilation failed: %v", err)
	}
	p3.Stop()
	encrypt3Constraints := ccs3.GetNbConstraints()

	// Print comparison
	fmt.Printf("Standard Encrypt:   %d constraints\n", encryptConstraints)
	fmt.Printf("Optimized Encrypt: %d constraints (fixed-base)\n", encrypt3Constraints)

	diff3 := int(encrypt3Constraints) - int(encryptConstraints)
	if diff3 < 0 {
		fmt.Printf("\nEncrypt vs Encrypt(old): %d constraints saved (%.2f%% reduction)\n", -diff3, float64(-diff3)/float64(encryptConstraints)*100)
	} else {
		fmt.Printf("\nEncrypt vs Encrypt(old): %d extra constraints (%.2f%% increase)\n", diff3, float64(diff3)/float64(encryptConstraints)*100)
	}

	fmt.Println("\nAnalysis:")
	fmt.Printf("- Single ScalarMul: ~2401 constraints\n")
	fmt.Printf("- Standard Encrypt uses: 3 ScalarMuls + 1 Add = ~7200 constraints\n")
	fmt.Printf("- Optimized Encrypt uses: 2 Fixed-base ScalarMuls + 1 Variable-base ScalarMul\n")
	fmt.Printf("- Fixed-base optimization reduces each [k]*G and [m]*G significantly\n")
	fmt.Println("=====================================")
}
