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
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
	"github.com/vocdoni/gnark-crypto-primitives/testutil"
	"go.vocdoni.io/dvote/util"
)

type testVerifierBN254 struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [160]frontend.Variable
}

func (circuit *testVerifierBN254) Define(api frontend.API) error {
	// use poseidon hash function
	return CheckInclusionProof(api, poseidon.Hash, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
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
	testCensus, err := testutil.GenerateCensusProofForTest(testutil.CensusTestConfig{
		Dir:           t.TempDir() + "/bn254",
		ValidSiblings: v_siblings,
		TotalSiblings: n_siblings,
		KeyLen:        k_len,
		Hash:          arbotree.HashFunctionPoseidon,
		BaseFiled:     arbotree.BN254BaseField,
	}, util.RandomBytes(k_len), big.NewInt(10).Bytes())
	c.Assert(err, qt.IsNil)
	// init and print inputs
	fSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		fSiblings[i] = testCensus.Siblings[i]
	}
	inputs := testVerifierBN254{
		Root:     testCensus.Root,
		Key:      testCensus.Key,
		Value:    testCensus.Value,
		Siblings: fSiblings,
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifierBN254{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
