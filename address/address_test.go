package address

import (
	"fmt"
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
	internaltest "github.com/vocdoni/gnark-crypto-primitives/test"
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
	// compile the circuit and get the constraints
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &testAddressCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// hash a test message and sign it
	input := crypto.Keccak256Hash([]byte("hello")).Bytes()
	testSig, err := internaltest.GenerateAccountAndSign(input)
	c.Assert(err, qt.IsNil)
	// init inputs
	witness := testAddressCircuit{
		Address: testSig.Address,
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](testSig.PublicKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](testSig.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testAddressCircuit{}, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.GROTH16))
}
