package poseidon

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	hash "github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/hash/poseidon"
)

type testPoseidonCiruit struct {
	Data frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *testPoseidonCiruit) Define(api frontend.API) error {
	h, err := Hash(api, circuit.Data)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, circuit.Hash)
	return nil
}

func TestPoseidon(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, assignment testPoseidonCiruit

	input, _ := new(big.Int).SetString("297262668938251460872476410954775437897592223497", 10)
	assignment.Data = input
	assignment.Hash, _ = hash.Hash([]*big.Int{input})

	assert.SolvingSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type testMultiPoseidonCircuit struct {
	Data [32]frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *testMultiPoseidonCircuit) Define(api frontend.API) error {
	h, err := MultiHash(api, circuit.Data[:]...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, circuit.Hash)
	return nil
}

func TestMultiPoseidon(t *testing.T) {
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testMultiPoseidonCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())

	var (
		inputs [32]*big.Int
		data   [32]frontend.Variable
	)
	for i := 0; i < 32; i++ {
		// generate random input
		r, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = r
		data[i] = r
	}
	hash, err := poseidon.MultiPoseidon(inputs[:]...)
	if err != nil {
		t.Fatal(err)
	}
	witness := &testMultiPoseidonCircuit{
		Data: data,
		Hash: hash,
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testMultiPoseidonCircuit{}, witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
