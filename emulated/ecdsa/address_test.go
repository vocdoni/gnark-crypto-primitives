package ecdsa

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
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/gnark-crypto-primitives/testutil"
)

type testAddressCircuit struct {
	Address             frontend.Variable `gnark:",public"`
	AddressLittleEndian frontend.Variable `gnark:",public"`
	PublicKey           gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
}

func (c *testAddressCircuit) Define(api frontend.API) error {
	addr, addrLE, err := DeriveAddress(api, c.PublicKey)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Address, addr)
	api.AssertIsEqual(c.AddressLittleEndian, addrLE)
	return nil
}

func goSwapEndianness(b []byte) []byte {
	var swap []byte
	for i := len(b) - 1; i >= 0; i-- {
		swap = append(swap, b[i])
	}
	return swap
}

func TestAddressDerivation(t *testing.T) {
	c := qt.New(t)
	// compile the circuit and get the constraints
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testAddressCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// hash a test message and sign it
	input := crypto.Keccak256Hash([]byte("hello")).Bytes()
	testSig, err := testutil.GenerateAccountAndSign(input)
	c.Assert(err, qt.IsNil)
	addrLE := new(big.Int).SetBytes(goSwapEndianness(testSig.Address.Bytes()))
	// init inputs
	witness := testAddressCircuit{
		Address:             testSig.Address,
		AddressLittleEndian: addrLE,
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](testSig.PublicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](testSig.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testAddressCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
