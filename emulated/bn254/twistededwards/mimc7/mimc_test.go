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
