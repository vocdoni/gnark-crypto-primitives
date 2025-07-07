package mimc7

import (
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/davinci-node/util"
)

type testMiMCCircuit struct {
	Hash     emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Preimage emulated.Element[sw_bn254.ScalarField]
}

func (circuit *testMiMCCircuit) Define(api frontend.API) error {
	mimc, err := NewMiMC(api)
	if err != nil {
		return err
	}
	if err := mimc.Write(circuit.Preimage); err != nil {
		api.Println(err.Error())
		api.AssertIsEqual(1, 0)
	}
	mimc.AssertSumIsEqual(circuit.Hash)
	return nil
}

func TestMiMC(t *testing.T) {
	c := qt.New(t)
	// generate a random input and hash it
	input := new(big.Int).SetInt64(12)
	hash, err := mimc7.Hash([]*big.Int{input}, nil)
	c.Assert(err, qt.IsNil)
	c.Assert(printConstrains(&testMiMCCircuit{}), qt.IsNil)
	// create a witness
	witness := testMiMCCircuit{
		Preimage: emulated.ValueOf[sw_bn254.ScalarField](input),
		Hash:     emulated.ValueOf[sw_bn254.ScalarField](hash),
	}
	// run the test
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&testMiMCCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
	fmt.Println("solving tooks", time.Since(now))
}

type testMaxInputsMiMCCircuit struct {
	Hash      emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Preimages [maxInputs]emulated.Element[sw_bn254.ScalarField]
}

func (circuit *testMaxInputsMiMCCircuit) Define(api frontend.API) error {
	mimc, err := NewMiMC(api)
	if err != nil {
		return err
	}
	if err := mimc.Write(circuit.Preimages[:]...); err != nil {
		api.Println(err.Error())
		api.AssertIsEqual(1, 0)
	}
	mimc.AssertSumIsEqual(circuit.Hash)
	return nil
}

type testLimitInputsMiMCCircuit struct {
	Preimages [maxInputs + 1]emulated.Element[sw_bn254.ScalarField]
}

func (circuit *testLimitInputsMiMCCircuit) Define(api frontend.API) error {
	mimc, err := NewMiMC(api)
	if err != nil {
		return err
	}
	if err := mimc.Write(circuit.Preimages[:]...); err == nil {
		api.Println("too many inputs expected")
		api.AssertIsEqual(1, 0)
	}
	return nil
}

func TestMaxAndLimitInputsMiMC(t *testing.T) {
	c := qt.New(t)
	// generate a random inputs
	input := arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(util.RandomBytes(32)))
	inputs := []*big.Int{}
	emulatedInputs := [maxInputs]emulated.Element[sw_bn254.ScalarField]{}
	limitEmulatedInputs := [maxInputs + 1]emulated.Element[sw_bn254.ScalarField]{}
	for i := 0; i < maxInputs; i++ {
		inputs = append(inputs, input)
		emulatedInputs[i] = emulated.ValueOf[sw_bn254.ScalarField](input)
		limitEmulatedInputs[i] = emulated.ValueOf[sw_bn254.ScalarField](input)
	}
	limitEmulatedInputs[maxInputs] = emulated.ValueOf[sw_bn254.ScalarField](input)

	c.Run("max inputs", func(c *qt.C) {
		// hash the max inputs
		maxHash, err := mimc7.Hash(inputs, nil)
		c.Assert(err, qt.IsNil)
		// run the test
		assert := test.NewAssert(t)
		assert.SolvingSucceeded(&testMaxInputsMiMCCircuit{}, &testMaxInputsMiMCCircuit{
			Preimages: emulatedInputs,
			Hash:      emulated.ValueOf[sw_bn254.ScalarField](maxHash),
		}, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
	})

	c.Run("limit inputs", func(c *qt.C) {
		assert := test.NewAssert(t)
		assert.SolvingSucceeded(&testLimitInputsMiMCCircuit{}, &testLimitInputsMiMCCircuit{
			Preimages: limitEmulatedInputs,
		}, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
	})
}

func printConstrains(placeholder frontend.Circuit) error {
	// compile circuit
	p := profile.Start()
	now := time.Now()
	_, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, placeholder)
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Println("compilation tooks", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	return nil
}
