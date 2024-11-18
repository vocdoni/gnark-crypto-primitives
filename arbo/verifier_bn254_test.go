package arbo

import (
	"encoding/json"
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
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
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
	return CheckProof(api, poseidon.Hash, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
}

func TestVerifierBN254(t *testing.T) {
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testVerifierBN254{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// generate census proof
	root, key, value, siblings, err := generateCensusProof(censusConfig{
		dir:           t.TempDir() + "/bn254",
		validSiblings: v_siblings,
		totalSiblings: n_siblings,
		keyLen:        k_len,
		hash:          arbotree.HashFunctionPoseidon,
		baseFiled:     arbotree.BN254BaseField,
	}, util.RandomBytes(k_len), big.NewInt(10).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// init and print inputs
	fSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		fSiblings[i] = siblings[i]
	}
	inputs := testVerifierBN254{
		Root:     root,
		Key:      key,
		Value:    value,
		Siblings: fSiblings,
	}
	binputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	fmt.Println("inputs", string(binputs))
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifierBN254{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
