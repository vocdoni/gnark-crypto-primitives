package hadd

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/vocdoni/vocdoni-z-sandbox/ecc/format"
)

type testHomomorphicAddCircuit struct {
	A1 twistededwards.Point `gnark:"a1,public"`
	A2 twistededwards.Point `gnark:"a2,public"`
	B1 twistededwards.Point `gnark:"b1,public"`
	B2 twistededwards.Point `gnark:"b2,public"`
	C1 twistededwards.Point `gnark:"c1,public"`
	C2 twistededwards.Point `gnark:"c2,public"`
}

func (c *testHomomorphicAddCircuit) Define(api frontend.API) error {
	// calculate and check c1
	c1, err := HomomorphicAdd(api, c.A1, c.B1)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.C1.X, c1.X)
	api.AssertIsEqual(c.C1.Y, c1.Y)
	// calculate and check c2
	c2, err := HomomorphicAdd(api, c.A2, c.B2)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.C2.X, c2.X)
	api.AssertIsEqual(c.C2.Y, c2.Y)
	return nil
}

func TestHomomorphicAdd(t *testing.T) {
	// generate a public mocked key and a random k to encrypt first message
	_, pubKey := generateKeyPair()
	k1, err := randomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	// encrypt a simple message
	msg1 := big.NewInt(3)
	a1, a2 := encrypt(msg1, pubKey, k1)
	// reduce the points to reduced twisted edwards form
	xA1RTE, yA1RTE := format.FromTEtoRTE(a1.X, a1.Y)
	xA2RTE, yA2RTE := format.FromTEtoRTE(a2.X, a2.Y)
	// generate a second random k to encrypt a second message
	k2, err := randomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	// encrypt a second simple message
	msg2 := big.NewInt(5)
	b1, b2 := encrypt(msg2, pubKey, k2)
	// reduce the points to reduced twisted edwards form
	xB1RTE, yB1RTE := format.FromTEtoRTE(b1.X, b1.Y)
	xB2RTE, yB2RTE := format.FromTEtoRTE(b2.X, b2.Y)
	// calculate the sum of the encrypted messages to check the homomorphic property
	c1 := new(babyjub.PointProjective).Add(a1.Projective(), b1.Projective()).Affine()
	c2 := new(babyjub.PointProjective).Add(a2.Projective(), b2.Projective()).Affine()
	// reduce the points to reduced twisted edwards form
	xC1RTE, yC1RTE := format.FromTEtoRTE(c1.X, c1.Y)
	xC2RTE, yC2RTE := format.FromTEtoRTE(c2.X, c2.Y)
	// profiling the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testHomomorphicAddCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// run the test to prove the homomorphic property
	assert := test.NewAssert(t)
	inputs := &testHomomorphicAddCircuit{
		A1: twistededwards.Point{
			X: xA1RTE,
			Y: yA1RTE,
		},
		A2: twistededwards.Point{
			X: xA2RTE,
			Y: yA2RTE,
		},
		B1: twistededwards.Point{
			X: xB1RTE,
			Y: yB1RTE,
		},
		B2: twistededwards.Point{
			X: xB2RTE,
			Y: yB2RTE,
		},
		C1: twistededwards.Point{
			X: xC1RTE,
			Y: yC1RTE,
		},
		C2: twistededwards.Point{
			X: xC2RTE,
			Y: yC2RTE,
		},
	}
	now = time.Now()
	assert.SolvingSucceeded(&testHomomorphicAddCircuit{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	fmt.Println("elapsed", time.Since(now))
}

func randomK() (*big.Int, error) {
	// Generate random scalar k
	kBytes := make([]byte, 32)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}

	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, babyjub.SubOrder)
	return k, nil
}

func generateKeyPair() (babyjub.PrivateKey, *babyjub.PublicKey) {
	privkey := babyjub.NewRandPrivKey()
	return privkey, privkey.Public()
}

func encrypt(message *big.Int, publicKey *babyjub.PublicKey, k *big.Int) (*babyjub.Point, *babyjub.Point) {
	// c1 = [k] * G
	c1 := babyjub.NewPoint().Mul(k, babyjub.B8)
	// s = [k] * publicKey
	s := babyjub.NewPoint().Mul(k, publicKey.Point())
	// m = [message] * G
	m := babyjub.NewPoint().Mul(message, babyjub.B8)
	// c2 = m + s
	c2p := babyjub.NewPointProjective().Add(m.Projective(), s.Projective())
	return c1, c2p.Affine()
}
