package smt

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

type testProcessorWithLeafHashCircuit struct {
	OldRoot  frontend.Variable
	Siblings [4]frontend.Variable
	OldKey   frontend.Variable
	OldValue frontend.Variable
	IsOld0   frontend.Variable
	NewKey   frontend.Variable
	NewValue frontend.Variable
	Fnc0     frontend.Variable
	Fnc1     frontend.Variable
	NewRoot  frontend.Variable
}

func (c *testProcessorWithLeafHashCircuit) Define(api frontend.API) error {
	hash1Old := Hash1(api, utils.PoseidonHasher, c.OldKey, c.OldValue)
	hash1New := Hash1(api, utils.PoseidonHasher, c.NewKey, c.NewValue)
	newRoot := ProcessorWithLeafHash(
		api,
		utils.PoseidonHasher,
		c.OldRoot,
		c.Siblings[:],
		c.OldKey,
		hash1Old,
		c.IsOld0,
		c.NewKey,
		hash1New,
		c.Fnc0,
		c.Fnc1,
	)
	api.AssertIsEqual(newRoot, c.NewRoot)
	return nil
}

func TestProcessorWithLeafHashRejectsNonBooleanIsOld0(t *testing.T) {
	valid := &testProcessorWithLeafHashCircuit{
		OldRoot:  0,
		Siblings: [4]frontend.Variable{0, 0, 0, 0},
		OldKey:   0,
		OldValue: 0,
		IsOld0:   0,
		NewKey:   0,
		NewValue: 0,
		Fnc0:     0,
		Fnc1:     0,
		NewRoot:  0,
	}

	invalid := *valid
	invalid.IsOld0 = 2

	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&testProcessorWithLeafHashCircuit{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(&invalid),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}
