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
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	arbotree "github.com/vocdoni/arbo"
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

	return CheckProof(api, hash, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
}

func TestVerifierBLS12377(t *testing.T) {
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testVerifierBLS12377{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// generate census proof
	root, key, value, siblings, err := generateCensusProof(censusConfig{
		validSiblings: v_siblings,
		totalSiblings: n_siblings,
		keyLen:        k_len,
		hash:          arbotree.HashFunctionMiMC_BLS12_377,
		baseFiled:     arbotree.BLS12377BaseField,
	}, util.RandomBytes(k_len), big.NewInt(10).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// init and print inputs
	fSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		fSiblings[i] = siblings[i]
	}
	inputs := testVerifierBLS12377{
		Root:     root,
		Key:      key,
		Value:    value,
		Siblings: fSiblings,
	}
	binputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	fmt.Println("inputs", string(binputs))
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifierBLS12377{}, &inputs, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
