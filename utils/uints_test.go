package utils

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
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
