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
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/testutil"
	"go.vocdoni.io/dvote/util"
)

const (
	v_siblings = 10
	n_siblings = 160
	k_len      = n_siblings / 8
)

type testVerifierBLS12377 struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [n_siblings]frontend.Variable
}

func (circuit *testVerifierBLS12377) Define(api frontend.API) error {
	// use mimc hash function
	hash := func(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
		h, err := mimc.NewMiMC(api)
		if err != nil {
			return 0, err
		}
		h.Write(data...)
		return h.Sum(), nil
	}
	return CheckInclusionProof(api, hash, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
}

func TestVerifierBLS12377(t *testing.T) {
	c := qt.New(t)
	// profile the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testVerifierBLS12377{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// generate census proof
	testCensus, err := testutil.GenerateCensusProofForTest(testutil.CensusTestConfig{
		Dir:           t.TempDir() + "/bls12377",
		ValidSiblings: v_siblings,
		TotalSiblings: n_siblings,
		KeyLen:        k_len,
		Hash:          arbotree.HashFunctionMiMC_BLS12_377,
		BaseField:     arbotree.BLS12377BaseField,
	}, [][]byte{util.RandomBytes(k_len)}, [][]byte{big.NewInt(10).Bytes()})
	c.Assert(err, qt.IsNil)
	// init and print inputs
	fSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		fSiblings[i] = testCensus.Proofs[0].Siblings[i]
	}
	inputs := testVerifierBLS12377{
		Root:     testCensus.Root,
		Key:      testCensus.Proofs[0].Key,
		Value:    testCensus.Proofs[0].Value,
		Siblings: fSiblings,
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifierBLS12377{}, &inputs, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
