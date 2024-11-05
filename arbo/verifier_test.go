package arbo

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/pebbledb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/util"
)

type testVerifierCircuit struct {
	Root      frontend.Variable
	Key       frontend.Variable
	Value     frontend.Variable
	NSiblings frontend.Variable
	Siblings  [160]frontend.Variable
}

func (circuit *testVerifierCircuit) Define(api frontend.API) error {
	return CheckProof(api, circuit.Key, circuit.Value, circuit.Root, circuit.NSiblings, circuit.Siblings[:])
}

func successInputs(t *testing.T, n int) testVerifierCircuit {
	c := qt.New(t)

	database, err := pebbledb.New(db.Options{Path: t.TempDir()})
	c.Assert(err, qt.IsNil)
	tree, err := arbo.NewTree(arbo.Config{
		Database:     database,
		MaxLevels:    160,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	key := util.BigToFF(new(big.Int).SetBytes(util.RandomBytes(20))).Bytes()
	value := big.NewInt(10)

	err = tree.Add(key, value.Bytes())
	c.Assert(err, qt.IsNil)

	for i := 1; i < n; i++ {
		err = tree.Add(util.BigToFF(new(big.Int).SetBytes(util.RandomBytes(20))).Bytes(), value.Bytes())
		c.Assert(err, qt.IsNil)
	}

	tkey, tvalue, pSiblings, exist, err := tree.GenProof(key)
	c.Assert(err, qt.IsNil)
	c.Assert(exist, qt.IsTrue)
	c.Assert(tkey, qt.ContentEquals, key)
	c.Assert(tvalue, qt.ContentEquals, value.Bytes())

	uSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, pSiblings)
	c.Assert(err, qt.IsNil)

	siblings := [160]frontend.Variable{}
	for i := 0; i < 160; i++ {
		if i < len(uSiblings) {
			siblings[i] = arbo.BytesLEToBigInt(uSiblings[i])
		} else {
			siblings[i] = big.NewInt(0)
		}
	}

	root, err := tree.Root()
	c.Assert(err, qt.IsNil)
	return testVerifierCircuit{
		Root:      arbo.BytesLEToBigInt(root),
		Key:       arbo.BytesLEToBigInt(key),
		Value:     value,
		Siblings:  siblings,
		NSiblings: new(big.Int).SetInt64(int64(len(uSiblings))),
	}
}

func TestVerifier(t *testing.T) {
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testVerifierCircuit{})
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())

	assert := test.NewAssert(t)

	inputs := successInputs(t, 10)
	assert.SolvingSucceeded(&testVerifierCircuit{}, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
