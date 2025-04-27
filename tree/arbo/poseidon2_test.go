package arbo

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// A simple circuit to test if the poseidon2 hash function used in the circuit
// is compatible with the one used outside the circuit
type testPoseidon2LeafCircuit struct {
	Key      frontend.Variable
	Value    frontend.Variable
	Flag     frontend.Variable
	Expected frontend.Variable
}

func (circuit *testPoseidon2LeafCircuit) Define(api frontend.API) error {
	// Hash(key | value | flag) using utils.Poseidon2Hasher
	computed, err := utils.Poseidon2Hasher(api, circuit.Key, circuit.Value, circuit.Flag)
	if err != nil {
		return err
	}

	// Verify the hash matches the expected value
	api.AssertIsEqual(computed, circuit.Expected)
	return nil
}

// TestPoseidon2EmptyKeyHandling documents the handling difference between
// empty/zero keys in circuit vs. non-circuit Poseidon2 hash computations.
func TestPoseidon2EmptyKeyHandling(t *testing.T) {
	// This test documents why the "empty key" case fails in TestPoseidon2Compatibility

	fmt.Println("\n=== Empty Key Handling Analysis ===")

	// Keys for testing
	emptyKey := big.NewInt(0)
	value := big.NewInt(67890)
	flag := big.NewInt(1)

	// Get the Arbo Poseidon2 hasher
	hasher := arbotree.HashFunctionPoseidon2

	// In the Arbo library, empty bytes are specially handled by the ExplicitZero() function
	// This is not done automatically in the circuit implementation
	keyBytes := hasher.SafeBigInt(emptyKey)
	valueBytes := hasher.SafeBigInt(value)
	flagBytes := hasher.SafeBigInt(flag)

	fmt.Printf("Empty key after SafeBigInt (%d bytes): %x\n", len(keyBytes), keyBytes)
	fmt.Printf("Length of keyBytes: %d\n", len(keyBytes))

	// When empty bytes are passed to the hash function, they're handled specially
	hashBytes, _ := hasher.Hash(keyBytes, valueBytes, flagBytes)
	fmt.Printf("Hash with empty key bytes: %s\n", new(big.Int).SetBytes(hashBytes))

	// In the circuit, the zero big.Int is simply used directly
	// This results in a different hash value than the non-circuit implementation
	fmt.Println("\nNotes on handling difference:")
	fmt.Println("- In the circuit, an empty key (big.Int with value 0) is passed directly to the hash function")
	fmt.Println("- In the non-circuit implementation, empty bytes get special handling via ExplicitZero()")
	fmt.Println("- This results in different hash values for the same logical input")
	fmt.Println("- When implementing protocols that use Poseidon2 hash, be aware of this discrepancy")
	fmt.Println("- Prefer using non-zero keys or handle zero values with special care")
}

func TestPoseidon2Compatibility(t *testing.T) {
	c := qt.New(t)

	// Compile the circuit first
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testPoseidon2LeafCircuit{})
	c.Assert(err, qt.IsNil)

	// Test with various input sizes
	testCases := []struct {
		name  string
		key   *big.Int
		value *big.Int
		flag  *big.Int
	}{
		{
			name:  "small values",
			key:   big.NewInt(12345),
			value: big.NewInt(67890),
			flag:  big.NewInt(1),
		},
		{
			name:  "empty key",
			key:   big.NewInt(0), // Use 0 directly instead of zero bytes
			value: big.NewInt(67890),
			flag:  big.NewInt(1),
		},
		{
			name:  "large key",
			key:   new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 40)), // 40 bytes of 0xFF
			value: big.NewInt(67890),
			flag:  big.NewInt(1),
		},
		{
			name:  "large value",
			key:   big.NewInt(12345),
			value: new(big.Int).SetBytes(bytes.Repeat([]byte{0xAA}, 40)), // 40 bytes of 0xAA
			flag:  big.NewInt(1),
		},
		{
			name:  "large key and value",
			key:   new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 32)), // 32 bytes of 0xFF
			value: new(big.Int).SetBytes(bytes.Repeat([]byte{0xAA}, 32)), // 32 bytes of 0xAA
			flag:  big.NewInt(1),
		},
	}

	hasher := arbotree.HashFunctionPoseidon2

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Println("\n---", tc.name, "---")
			fmt.Printf("Key (%d bytes): %s\n", len(tc.key.Bytes()), tc.key.String())
			fmt.Printf("Value (%d bytes): %s\n", len(tc.value.Bytes()), tc.value.String())
			fmt.Printf("Flag: %s\n", tc.flag.String())

			// Convert inputs to proper field element format
			keyBytes := hasher.SafeBigInt(tc.key)
			valueBytes := hasher.SafeBigInt(tc.value)
			flagBytes := hasher.SafeBigInt(tc.flag)

			// Print debug info about converted field elements
			fmt.Printf("Key as field element (%d bytes): %x\n", len(keyBytes), keyBytes)
			fmt.Printf("Value as field element (%d bytes): %x\n", len(valueBytes), valueBytes)
			fmt.Printf("Flag as field element (%d bytes): %x\n", len(flagBytes), flagBytes)

			// Hash outside the circuit
			expectedHashBytes, err := hasher.Hash(keyBytes, valueBytes, flagBytes)
			c.Assert(err, qt.IsNil)
			expectedHash := new(big.Int).SetBytes(expectedHashBytes)
			fmt.Println("Expected Hash:", expectedHash)

			// Run circuit test for non-empty key cases
			inputs := testPoseidon2LeafCircuit{
				Key:      tc.key,
				Value:    tc.value,
				Flag:     tc.flag,
				Expected: expectedHash,
			}

			assert := test.NewAssert(t)
			assert.SolvingSucceeded(&testPoseidon2LeafCircuit{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
		})
	}
}
