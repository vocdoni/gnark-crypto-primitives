package arbo

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	arbotree "github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

const (
	n_siblings = 160
	k_len      = n_siblings / 8
)

type testVerifierCircuit struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [n_siblings]frontend.Variable
}

func (circuit *testVerifierCircuit) Define(api frontend.API) error {
	return CheckProof(api, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
}

func TestVerifier(t *testing.T) {
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testVerifierCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())

	assert := test.NewAssert(t)
	inputs, err := generateCensusProof(10, util.RandomBytes(k_len), big.NewInt(10).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	binputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	fmt.Println("inputs", string(binputs))
	assert.SolvingSucceeded(&testVerifierCircuit{}, &inputs, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}

func generateCensusProof(n int, k, v []byte) (testVerifierCircuit, error) {
	dir := os.TempDir()
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	database, err := pebbledb.New(db.Options{Path: dir})
	if err != nil {
		return testVerifierCircuit{}, err
	}
	tree, err := arbotree.NewTree(arbotree.Config{
		Database:     database,
		MaxLevels:    n_siblings,
		HashFunction: arbotree.HashFunctionMiMC_BLS12_377,
	})
	if err != nil {
		return testVerifierCircuit{}, err
	}

	k = arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(k)).Bytes()
	// add the first key-value pair
	if err = tree.Add(k, v); err != nil {
		return testVerifierCircuit{}, err
	}
	// add random addresses
	for i := 1; i < n; i++ {
		rk := arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(util.RandomBytes(k_len))).Bytes()
		rv := new(big.Int).SetBytes(util.RandomBytes(8)).Bytes()
		if err = tree.Add(rk, rv); err != nil {
			return testVerifierCircuit{}, err
		}
	}
	// generate the proof
	_, _, siblings, exist, err := tree.GenProof(k)
	if err != nil {
		return testVerifierCircuit{}, err
	}
	if !exist {
		return testVerifierCircuit{}, fmt.Errorf("error building the merkle tree: key not found")
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, siblings)
	if err != nil {
		return testVerifierCircuit{}, err
	}
	paddedSiblings := [n_siblings]frontend.Variable{}
	for i := 0; i < n_siblings; i++ {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	root, err := tree.Root()
	if err != nil {
		return testVerifierCircuit{}, err
	}
	verified, err := arbotree.CheckProof(tree.HashFunction(), k, v, root, siblings)
	if !verified {
		return testVerifierCircuit{}, fmt.Errorf("error verifying the proof")
	}
	if err != nil {
		return testVerifierCircuit{}, err
	}
	return testVerifierCircuit{
		Root:     arbo.BytesLEToBigInt(root),
		Key:      arbo.BytesLEToBigInt(k),
		Value:    new(big.Int).SetBytes(v),
		Siblings: paddedSiblings,
	}, nil
}
