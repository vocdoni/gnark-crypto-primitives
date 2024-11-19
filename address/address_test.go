package address

import (
	"crypto/rand"
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
	"github.com/iden3/go-iden3-crypto/keccak256"
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
	input := []byte("test")
	// generate ecdsa key pair (privKey and publicKey)
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := []byte{}
	for _, b := range privKey.PublicKey.A.X.Bytes() {
		pubBytes = append(pubBytes, b)
	}
	for _, b := range privKey.PublicKey.A.Y.Bytes() {
		pubBytes = append(pubBytes, b)
	}
	hash := keccak256.Hash(pubBytes)
	// compute the signature of an arbitrary message
	sigBin, err := privKey.Sign(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if flag, err := privKey.PublicKey.Verify(sigBin, input, nil); !flag || err != nil {
		t.Fatal("invalid signature")
	}
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	// get the address from the hash of the public key (taking the last 20 bytes
	// of the Keccak-256 hash of the public key)
	address := new(big.Int).SetBytes(hash[12:])
	// compile the circuit and get the constraints
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testAddressCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// init inputs
	witness := testAddressCircuit{
		Address: address,
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testAddressCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
