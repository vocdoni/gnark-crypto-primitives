package mimc7

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/davinci-node/util"
)

type testMiMCCircuit struct {
	Hash     frontend.Variable `gnark:",public"`
	Preimage frontend.Variable
}

func (circuit *testMiMCCircuit) Define(api frontend.API) error {
	mimc, err := New(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Preimage)
	mimc.AssertSumIsEqual(circuit.Hash)
	return nil
}

func TestMiMC(t *testing.T) {
	c := qt.New(t)
	// generate a random input and hash it
	input := new(big.Int).SetInt64(12)
	hash, err := mimc7.Hash([]*big.Int{input}, nil)
	c.Assert(err, qt.IsNil)
	// c.Assert(printConstrains(&testMiMCCircuit{}), qt.IsNil)
	// create a witness
	witness := testMiMCCircuit{
		Preimage: input,
		Hash:     hash,
	}
	// run the test
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&testMiMCCircuit{}, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	fmt.Println("solving tooks", time.Since(now))
}

type testMaxInputsMiMCCircuit struct {
	Hash      frontend.Variable `gnark:",public"`
	Preimages [maxInputs]frontend.Variable
}

func (circuit *testMaxInputsMiMCCircuit) Define(api frontend.API) error {
	mimc, err := New(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Preimages[:]...)
	mimc.AssertSumIsEqual(circuit.Hash)
	return nil
}

type testLimitInputsMiMCCircuit struct {
	Preimages [maxInputs + 1]frontend.Variable
}

func (circuit *testLimitInputsMiMCCircuit) Define(api frontend.API) error {
	mimc, err := New(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Preimages[:]...)
	return nil
}

func TestMaxAndLimitInputsMiMC(t *testing.T) {
	c := qt.New(t)
	// generate a random inputs
	input := arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(util.RandomBytes(32)))
	inputs := []*big.Int{}
	emulatedInputs := [maxInputs]frontend.Variable{}
	limitEmulatedInputs := [maxInputs + 1]frontend.Variable{}
	for i := range maxInputs {
		inputs = append(inputs, input)
		emulatedInputs[i] = input
		limitEmulatedInputs[i] = input
	}
	limitEmulatedInputs[maxInputs] = input

	c.Run("max inputs", func(c *qt.C) {
		// hash the max inputs
		maxHash, err := mimc7.Hash(inputs, nil)
		c.Assert(err, qt.IsNil)
		// run the test
		assert := test.NewAssert(t)
		assert.SolvingSucceeded(&testMaxInputsMiMCCircuit{}, &testMaxInputsMiMCCircuit{
			Preimages: emulatedInputs,
			Hash:      maxHash,
		}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	})

	c.Run("limit inputs", func(c *qt.C) {
		assert := test.NewAssert(t)
		assert.SolvingSucceeded(&testLimitInputsMiMCCircuit{}, &testLimitInputsMiMCCircuit{
			Preimages: limitEmulatedInputs,
		}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	})
}
