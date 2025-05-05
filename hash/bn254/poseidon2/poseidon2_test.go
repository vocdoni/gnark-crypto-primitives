//go:build wasm || !wasm
// +build wasm !wasm

package poseidon2

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	poseidon1 "github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
)

type poseidon2CompatCircuit struct {
	// inputs (all field elements)
	A, B, C  frontend.Variable // C is ignored for 2-input case
	IsLeaf   frontend.Variable // 0 → internal-node ; 1 → leaf
	Expected frontend.Variable // native hash
}

func (c *poseidon2CompatCircuit) Define(api frontend.API) error {
	var got frontend.Variable
	var err error

	// internal node  (2 inputs)
	got, err = HashPoseidon2Gnark(api, c.A, c.B)
	if err != nil {
		return err
	}
	// leaf (3 inputs) – overwrite if IsLeaf==1
	leafHash, err := HashPoseidon2Gnark(api, c.A, c.B, c.C)
	if err != nil {
		return err
	}
	got = api.Select(c.IsLeaf, leafHash, got)
	api.AssertIsEqual(got, c.Expected)
	return nil
}

func randomFieldElement() *big.Int {
	b, _ := rand.Int(rand.Reader, BN254BaseField)
	return b
}

func canon(x *big.Int) []byte { return HashPoseidon2{}.SafeBigInt(x) }

func TestPoseidon2_Go_vs_Circuit(t *testing.T) {
	assert := test.NewAssert(t)

	cases := []struct {
		name   string
		isLeaf int64
		a, b   *big.Int
		c      *big.Int // nil for 2-input case
	}{
		{
			name:   "internal-node",
			isLeaf: 0,
			a:      randomFieldElement(),
			b:      randomFieldElement(),
			c:      nil,
		},
		{
			name:   "leaf",
			isLeaf: 1,
			a:      randomFieldElement(), // key
			b:      randomFieldElement(), // val
			c:      big.NewInt(1),        // flag = 1
		},
	}

	// compile the circuit
	_, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&poseidon2CompatCircuit{},
	)
	if err != nil {
		t.Fatal(err)
	}

	// run the test cases
	for _, tc := range cases {
		tc := tc // capture
		t.Run(tc.name, func(t *testing.T) {
			w := &poseidon2CompatCircuit{
				A:      tc.a,
				B:      tc.b,
				C:      big.NewInt(0), // Default value for C to avoid nil
				IsLeaf: tc.isLeaf,
			}
			var nativeHash []byte
			if tc.isLeaf == 1 {
				w.C = tc.c // Override the default value for leaf case
				nativeHash, err = HashFunctionPoseidon2.Hash(
					canon(tc.a), canon(tc.b), canon(tc.c),
				)
			} else {
				// internal node → order handled inside Hash()
				nativeHash, err = HashFunctionPoseidon2.Hash(
					canon(tc.a), canon(tc.b),
				)
			}
			if err != nil {
				t.Fatalf("native hash error: %v", err)
			}
			w.Expected = new(big.Int).SetBytes(nativeHash)

			assert.SolvingSucceeded(
				&poseidon2CompatCircuit{}, w,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
			)
		})
	}
}

// Constraint Comparison Test

type Poseidon1Circuit struct {
	Data []frontend.Variable
}

func (circuit *Poseidon1Circuit) Define(api frontend.API) error {
	h := poseidon1.NewPoseidon(api)
	if err := h.Write(circuit.Data...); err != nil {
		return err
	}
	h.Sum()
	return nil
}

type Poseidon2Circuit struct {
	Data []frontend.Variable
}

func (circuit *Poseidon2Circuit) Define(api frontend.API) error {
	_, err := HashPoseidon2Gnark(api, circuit.Data...)
	if err != nil {
		return err
	}
	return nil
}

func TestPoseidonConstraintComparison(t *testing.T) {
	ccs1, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Poseidon1Circuit{Data: make([]frontend.Variable, 2)})
	if err != nil {
		t.Fatal("failed to compile poseidon1 circuit:", err)
	}

	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Poseidon2Circuit{Data: make([]frontend.Variable, 2)})
	if err != nil {
		t.Fatal("failed to compile poseidon2 circuit:", err)
	}

	t.Logf("Poseidon1 constraints: %d", ccs1.GetNbConstraints())
	t.Logf("Poseidon2 constraints: %d", ccs2.GetNbConstraints())
	t.Logf("Constraint reduction: %.2f%%", 100.0*(1.0-float64(ccs2.GetNbConstraints())/float64(ccs1.GetNbConstraints())))
}
