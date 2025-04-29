package arbo

import (
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
	qt "github.com/frankban/quicktest"
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/testutil"
	"github.com/vocdoni/gnark-crypto-primitives/tree/smt"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"go.vocdoni.io/dvote/util"
)

type testPoseidon2HashVerifier struct {
	Input1   frontend.Variable
	Input2   frontend.Variable
	Expected frontend.Variable
}

func (circuit *testPoseidon2HashVerifier) Define(api frontend.API) error {
	// calculate hash using Poseidon2Hasher
	computed, err := utils.Poseidon2Hasher(api, circuit.Input1, circuit.Input2)
	if err != nil {
		return err
	}
	// verify the computed hash matches the expected hash
	api.AssertIsEqual(computed, circuit.Expected)
	return nil
}

type testVerifierBN254 struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [160]frontend.Variable
}

func (circuit *testVerifierBN254) Define(api frontend.API) error {
	// use poseidon2 hash function
	//valid := CheckInclusionProofFlag(api, utils.Poseidon2Hasher, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
	//api.AssertIsEqual(valid, 1)
	smt.InclusionVerifier(api, utils.Poseidon2Hasher, circuit.Root, circuit.Siblings[:], circuit.Key, circuit.Value)
	return nil
}

func TestPoseidon2HashVerifier(t *testing.T) {
	c := qt.New(t)

	// profile the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testPoseidon2HashVerifier{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constraints", p.NbConstraints())

	// generate inputs and compute expected hash
	input1 := big.NewInt(42)
	input2 := big.NewInt(123)

	// compute the hash using the same function but outside of the circuit
	hasher := arbotree.HashFunctionPoseidon2
	expectedHash, err := hasher.Hash(input1.Bytes(), input2.Bytes())
	c.Assert(err, qt.IsNil)

	// prepare inputs for the circuit
	inputs := testPoseidon2HashVerifier{
		Input1:   input1,
		Input2:   input2,
		Expected: new(big.Int).SetBytes(expectedHash),
	}

	// run the test
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testPoseidon2HashVerifier{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestVerifierBN254(t *testing.T) {
	c := qt.New(t)
	// profile the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testVerifierBN254{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// generate census proof
	testCensus, err := testutil.GenerateCensusProofForTest2(testutil.CensusTestConfig{
		Dir:           t.TempDir() + "/bn254",
		ValidSiblings: v_siblings,
		TotalSiblings: n_siblings,
		KeyLen:        k_len,
		Hash:          arbotree.HashFunctionPoseidon2,
		BaseField:     arbotree.BN254BaseField,
	}, [][]byte{util.RandomBytes(k_len)}, [][]byte{big.NewInt(10).Bytes()})
	c.Assert(err, qt.IsNil)
	// init and print inputs
	fSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		fSiblings[i] = testCensus.Proofs[0].Siblings[i]
	}
	inputs := testVerifierBN254{
		Root:     testCensus.Root,
		Key:      testCensus.Proofs[0].Key,
		Value:    testCensus.Proofs[0].Value,
		Siblings: fSiblings,
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifierBN254{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
