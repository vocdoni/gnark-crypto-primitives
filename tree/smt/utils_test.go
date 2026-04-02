package smt

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type testLowBitsCircuit struct {
	Key frontend.Variable
}

func (c *testLowBitsCircuit) Define(api frontend.API) error {
	bits := lowBits(api, c.Key, 3)
	api.AssertIsEqual(bits[0], 1)
	api.AssertIsEqual(bits[1], 1)
	api.AssertIsEqual(bits[2], 1)
	return nil
}

func TestLowBitsBindsToKey(t *testing.T) {
	assert := test.NewAssert(t)

	valid := &testLowBitsCircuit{Key: 7}
	invalid := &testLowBitsCircuit{Key: 5}

	assert.CheckCircuit(
		&testLowBitsCircuit{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(invalid),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)

	assert.CheckCircuit(
		&testLegacyLowBitsCircuit{},
		test.WithValidAssignment(invalid),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoTestEngine(),
		test.WithSolverOpts(solver.OverrideHint(solver.GetHintID(legacyRightShiftHint), maliciousRightShiftHint)),
	)
}

type testLegacyLowBitsCircuit struct {
	Key frontend.Variable
}

func (c *testLegacyLowBitsCircuit) Define(api frontend.API) error {
	bits := legacyLowBits(api, c.Key, 3)
	api.AssertIsEqual(bits[0], 1)
	api.AssertIsEqual(bits[1], 1)
	api.AssertIsEqual(bits[2], 1)
	return nil
}

func legacyLowBits(api frontend.API, val frontend.Variable, nBits int) []frontend.Variable {
	high, err := api.NewHint(legacyRightShiftHint, 1, val, nBits)
	if err != nil {
		panic(err)
	}

	base := big.NewInt(1)
	base.Lsh(base, uint(nBits))

	low := api.Sub(val, api.Mul(high[0], base))
	return api.ToBinary(low, nBits)
}

func legacyRightShiftHint(_ *big.Int, inputs, outputs []*big.Int) error {
	shift := inputs[1].Uint64()
	outputs[0].Rsh(inputs[0], uint(shift))
	return nil
}

func maliciousRightShiftHint(mod *big.Int, inputs, outputs []*big.Int) error {
	key := new(big.Int).Set(inputs[0])
	shift := inputs[1].Uint64()
	desiredLow := big.NewInt(7)
	base := new(big.Int).Lsh(big.NewInt(1), uint(shift))
	invBase := new(big.Int).ModInverse(base, mod)
	if invBase == nil {
		return fmt.Errorf("base %s is not invertible modulo field", base)
	}
	high := new(big.Int).Sub(key, desiredLow)
	high.Mul(high, invBase)
	high.Mod(high, mod)
	outputs[0].Set(high)
	return nil
}
