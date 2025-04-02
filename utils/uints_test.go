package utils

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

type testVarToU8Circuit struct {
	Input frontend.Variable
}

func (c *testVarToU8Circuit) Define(api frontend.API) error {
	u8s, err := VarToU8(api, c.Input)
	if err != nil {
		return err
	}
	v, err := U8ToVar(api, u8s)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Input, v)
	return nil
}

func TestVarToU8(t *testing.T) {
	assert := test.NewAssert(t)
	// generate a random big number
	r, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	assert.SolvingSucceeded(&testVarToU8Circuit{}, &testVarToU8Circuit{Input: r},
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(groth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}

type testElemToU8Circuit struct {
	Input emulated.Element[sw_bls12377.ScalarField]
}

func (c *testElemToU8Circuit) Define(api frontend.API) error {
	// Convert element to slice of uint8
	u8s, err := ElemToU8(api, c.Input)
	if err != nil {
		return err
	}

	// Convert back to element using our new function
	elem, err := U8ToElem[sw_bls12377.ScalarField](api, u8s)
	if err != nil {
		return err
	}

	// Check that limbs match
	for i, limb := range c.Input.Limbs {
		api.AssertIsEqual(limb, elem.Limbs[i])
	}

	return nil
}

func TestElemToU8(t *testing.T) {
	assert := test.NewAssert(t)

	// Generate a random big number
	r, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	// Create an emulated element
	elemValue := emulated.ValueOf[sw_bls12377.ScalarField](r)

	assert.SolvingSucceeded(&testElemToU8Circuit{}, &testElemToU8Circuit{Input: elemValue},
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(groth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
