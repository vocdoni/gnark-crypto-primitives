package eddsa

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
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/vocdoni/davinci-node/util"
	"github.com/vocdoni/gnark-crypto-primitives/hash/native"
)

type testEdDSAVerifierCircuit struct {
	PublicKey PublicKey `gnark:"public"`
	Signature Signature `gnark:"public"`
	Message   frontend.Variable
}

func (c *testEdDSAVerifierCircuit) Define(api frontend.API) error {
	hashFn, err := native.Poseidon(api)
	if err != nil {
		return err
	}
	verifier, err := NewVerifier(api, hashFn)
	if err != nil {
		return err
	}
	// Verify the signature
	res := verifier.IsValid(c.PublicKey, c.Signature, c.Message)
	api.AssertIsEqual(res, frontend.Variable(1))
	return nil
}

func TestVerifier(t *testing.T) {
	// Init Iden3 Private Key
	privKey := babyjub.NewRandPrivKey()
	// Generate a signature of random bytes
	msg := new(big.Int).SetBytes(util.RandomBytes(31))
	iden3Signature := privKey.SignPoseidon(msg)
	// Convert the signature to gnark format
	signature := SignatureFromIden3(iden3Signature)
	// Convert the public key to gnark format
	publicKey := PublicKeyFromIden3(privKey.Public())

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&testEdDSAVerifierCircuit{},
		&testEdDSAVerifierCircuit{
			PublicKey: publicKey,
			Signature: signature,
			Message:   msg,
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)

	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testEdDSAVerifierCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
}
