package elgamal

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
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

// CompatibilityCircuit verifies that optimized and standard implementations produce identical results
type CompatibilityCircuit struct {
	PubKey twistededwards.Point
	K      frontend.Variable
	M      frontend.Variable
}

// Define implements the circuit logic to verify compatibility
func (c *CompatibilityCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return err
	}

	// Get the base point (G)
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}

	// Standard implementation (using curve.ScalarMul)
	standardC1 := curve.ScalarMul(G, c.K)
	standardS := curve.ScalarMul(c.PubKey, c.K)
	standardMPoint := curve.ScalarMul(G, c.M)
	standardC2 := curve.Add(standardMPoint, standardS)

	// Optimized implementation (using Ciphertext.Encrypt with fixed-base)
	var optimizedCipher Ciphertext
	optimizedResult, err := optimizedCipher.Encrypt(api, c.PubKey, c.K, c.M)
	if err != nil {
		return err
	}

	// Assert that both implementations produce identical results
	api.AssertIsEqual(standardC1.X, optimizedResult.C1.X)
	api.AssertIsEqual(standardC1.Y, optimizedResult.C1.Y)
	api.AssertIsEqual(standardC2.X, optimizedResult.C2.X)
	api.AssertIsEqual(standardC2.Y, optimizedResult.C2.Y)

	// Test EncryptedZero compatibility: EncryptedZero(k) should equal Encrypt(k, 0)
	encryptedZeroResult := EncryptedZero(api, c.PubKey, c.K)

	// Encrypt with message = 0
	var encryptZeroCipher Ciphertext
	encryptZeroResult, err := encryptZeroCipher.Encrypt(api, c.PubKey, c.K, 0)
	if err != nil {
		return err
	}

	// Assert that EncryptedZero produces the same result as Encrypt(0)
	api.AssertIsEqual(encryptedZeroResult.C1.X, encryptZeroResult.C1.X)
	api.AssertIsEqual(encryptedZeroResult.C1.Y, encryptZeroResult.C1.Y)
	api.AssertIsEqual(encryptedZeroResult.C2.X, encryptZeroResult.C2.X)
	api.AssertIsEqual(encryptedZeroResult.C2.Y, encryptZeroResult.C2.Y)

	return nil
}

func TestEncryptCompatibility(t *testing.T) {
	assert := test.NewAssert(t)

	// Create witness with actual values
	edcurve := edbn254.GetEdwardsCurve()

	// Create a valid public key point (using base point for simplicity)
	var witness CompatibilityCircuit
	witness.PubKey.X = edcurve.Base.X
	witness.PubKey.Y = edcurve.Base.Y
	witness.K = 12345 // Random scalar for k
	witness.M = 67890 // Random scalar for m

	// Execute the proving system
	assert.SolvingSucceeded(&CompatibilityCircuit{}, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

// OptimizedEncryptOnlyCircuit tests only the optimized Encrypt implementation
type OptimizedEncryptOnlyCircuit struct {
	PubKey twistededwards.Point
	K      frontend.Variable
	M      frontend.Variable
}

// Define implements the circuit logic for testing optimized Encrypt only
func (c *OptimizedEncryptOnlyCircuit) Define(api frontend.API) error {
	// Use only the optimized implementation
	var cipher Ciphertext
	_, err := cipher.Encrypt(api, c.PubKey, c.K, c.M)
	if err != nil {
		return err
	}
	_ = EncryptedZero(api, c.PubKey, c.K)
	return nil
}

func TestEncryptWithSpecificData(t *testing.T) {
	assert := test.NewAssert(t)

	testCases := []struct {
		name string
		k    string
		m    string
	}{
		{
			name: "k1",
			k:    "855131146298194990003384743709896434741839908245",
			m:    "0",
		},
		{
			name: "k2",
			k:    "5883442530210657871581412827617735506655215369087356134218551734599178232070",
			m:    "0",
		},
		{
			name: "k3",
			k:    "3979028711588105728532079493967382119023185938755564152610807942458151212832",
			m:    "0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var witness OptimizedEncryptOnlyCircuit
			witness.PubKey.X = "18604149248430057540085528196797394191454458259161233471314599389622530831795"
			witness.PubKey.Y = "1988784568828097512630242539176296837964596457792502130892628909648459248949"
			witness.K = tc.k
			witness.M = tc.m

			// This should not panic or fail assertions with the optimized implementation
			assert.SolvingSucceeded(&OptimizedEncryptOnlyCircuit{}, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
		})
	}
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
}
