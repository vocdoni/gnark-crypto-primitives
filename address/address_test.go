package address

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	qt "github.com/frankban/quicktest"
)

type testAddressCircuit struct {
	Address   frontend.Variable `gnark:",public"`
	PublicKey gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
}

func (c *testAddressCircuit) Define(api frontend.API) error {
	addr, err := DeriveAddress(api, c.PublicKey)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Address, addr)
	return nil
}

func TestAddressDerivation(t *testing.T) {
	c := qt.New(t)

	input := crypto.Keccak256Hash([]byte("hello")).Bytes()
	// generate ecdsa key pair (privKey and publicKey)
	privKey, err := crypto.GenerateKey()
	c.Assert(err, qt.IsNil)
	sigBin, err := crypto.Sign(input, privKey)
	c.Assert(err, qt.IsNil)
	// truncate the signature to 64 bytes (the first 32 bytes are the R value,
	// the second 32 bytes are the S value)
	sigBin = sigBin[:64]
	valid := crypto.VerifySignature(crypto.CompressPubkey(&privKey.PublicKey), input, sigBin)
	c.Assert(valid, qt.IsTrue)
	var sig ecdsa.Signature
	_, err = sig.SetBytes(sigBin)
	c.Assert(err, qt.IsNil)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	// get the address from the hash of the public key (taking the last 20 bytes
	// of the Keccak-256 hash of the public key)
	address := crypto.PubkeyToAddress(privKey.PublicKey)
	// compile the circuit and get the constraints
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testAddressCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// init inputs
	witness := testAddressCircuit{
		Address: address.Big(),
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testAddressCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
