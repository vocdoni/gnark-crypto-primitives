package elgamal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/rs/zerolog"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
)

type testElGamalAddCircuit struct {
	A   Ciphertext `gnark:",public"`
	B   Ciphertext `gnark:",public"`
	Sum Ciphertext `gnark:",public"`
}

func (c *testElGamalAddCircuit) Define(api frontend.API) error {
	// calculate and check sum
	sum := &Ciphertext{}
	sum.Add(api, &c.A, &c.B)
	sum.AssertIsEqual(api, &c.Sum)
	return nil
}

func TestElGamalAdd(t *testing.T) {
	// generate a public mocked key and a random k to encrypt first message
	_, pubKey, err := generateKeyPair(nil)
	if err != nil {
		t.Fatalf("Error generating key pair: %v\n", err)
	}
	k1, err := randomK()
	if err != nil {
		t.Fatalf("Error generating random k: %v\n", err)
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
		t.Fatalf("Error generating random k: %v\n", err)
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
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testElGamalAddCircuit{})
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// run the test to prove the homomorphic property
	assert := test.NewAssert(t)
	inputs := &testElGamalAddCircuit{
		A: Ciphertext{
			C1: twistededwards.Point{
				X: xA1RTE,
				Y: yA1RTE,
			},
			C2: twistededwards.Point{
				X: xA2RTE,
				Y: yA2RTE,
			},
		},
		B: Ciphertext{
			C1: twistededwards.Point{
				X: xB1RTE,
				Y: yB1RTE,
			},
			C2: twistededwards.Point{
				X: xB2RTE,
				Y: yB2RTE,
			},
		},
		Sum: Ciphertext{
			C1: twistededwards.Point{
				X: xC1RTE,
				Y: yC1RTE,
			},
			C2: twistededwards.Point{
				X: xC2RTE,
				Y: yC2RTE,
			},
		},
	}
	now = time.Now()
	assert.SolvingSucceeded(&testElGamalAddCircuit{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	fmt.Println("elapsed", time.Since(now))
}

func randomK() (*big.Int, error) {
	// Generate random scalar k
	kBytes := make([]byte, 20)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}

	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, babyjub.SubOrder)
	return k, nil
}

func generateKeyPair(d *big.Int) (privateKey *big.Int, publicKey *babyjub.PublicKey, err error) {
	if d == nil {
		if d, err = rand.Int(rand.Reader, babyjub.SubOrder); err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key scalar: %v", err)
		}
	}
	if d.Sign() == 0 {
		d = big.NewInt(1) // avoid zero private keys
	}

	pubKey := babyjub.NewPoint().Mul(d, babyjub.B8)
	return d, (*babyjub.PublicKey)(pubKey), nil
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

type testElGamalEncryptCircuit struct {
	PrivKey frontend.Variable
	PubKey  twistededwards.Point `gnark:",public"`
	Result  Ciphertext           `gnark:",public"`
	K       frontend.Variable
	Msg     frontend.Variable
}

func (c *testElGamalEncryptCircuit) Define(api frontend.API) error {
	api.Println(c.PrivKey)
	res, err := new(Ciphertext).Encrypt(api, c.PubKey, c.K, c.Msg)
	if err != nil {
		return err
	}
	res.AssertIsEqual(api, &c.Result)
	return res.AssertDecrypt(api, c.PrivKey, c.Msg)
}

func TestEncryptAssertDecrypt(t *testing.T) {
	// generate a public mocked key and a random k to encrypt first message
	privKey, pubKey, err := generateKeyPair(nil)
	if err != nil {
		t.Fatalf("Error generating key pair: %v\n", err)
		return
	}
	k, err := randomK()
	if err != nil {
		t.Fatalf("Error generating random k: %v\n", err)
		return
	}
	// encrypt a simple message
	msg := big.NewInt(3)
	a1, a2 := encrypt(msg, pubKey, k)
	// reduce the points to reduced twisted edwards form
	xA1RTE, yA1RTE := format.FromTEtoRTE(a1.X, a1.Y)
	xA2RTE, yA2RTE := format.FromTEtoRTE(a2.X, a2.Y)

	pubKeyX, pubKeyY := format.FromTEtoRTE(pubKey.X, pubKey.Y)

	assignments := &testElGamalEncryptCircuit{
		PrivKey: privKey,
		PubKey: twistededwards.Point{
			X: pubKeyX,
			Y: pubKeyY,
		},
		Result: Ciphertext{
			C1: twistededwards.Point{
				X: xA1RTE,
				Y: yA1RTE,
			},
			C2: twistededwards.Point{
				X: xA2RTE,
				Y: yA2RTE,
			},
		},
		K:   k,
		Msg: msg,
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testElGamalEncryptCircuit{}, assignments,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

var HashFn = poseidon.MultiHash

type testVerifyDecryptionProofCircuit struct {
	PubKey     twistededwards.Point `gnark:",public"`
	Ciphertext Ciphertext           `gnark:",public"`
	Proof      DecryptionProof      `gnark:",public"`
	Msg        frontend.Variable
}

func (c *testVerifyDecryptionProofCircuit) Define(api frontend.API) error {
	// Verify the decryption proof
	return c.Proof.Verify(api, HashFn, c.PubKey, c.Ciphertext, c.Msg)
}

func TestVerifyDecryptionProof(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	mockMsg, _ := new(big.Int).SetString("50", 10)

	mockA1X, _ := new(big.Int).SetString("9394823613809705110116613460910105025054013892432913335394773002247992354854", 10)
	mockA1Y, _ := new(big.Int).SetString("11024289076895660735250094443495165598068433425499992095815117261086957091439", 10)
	mockA2X, _ := new(big.Int).SetString("19797710400961090194828422488006966273839297906754012108828771044254185248577", 10)
	mockA2Y, _ := new(big.Int).SetString("14922306070502274021207471871631487833716178512064982802994428541540403297523", 10)
	mockZ, _ := new(big.Int).SetString("1742022034800951303918649192268907782873437905421353131642789173698540722240", 10)

	pubKeyX, _ := new(big.Int).SetString("11914791603502957547081391328506057813324763482068493183947042790384502567641", 10)
	pubKeyY, _ := new(big.Int).SetString("14401335135320235427678361547570520415347209769899386704796044467443275407252", 10)

	c1X, _ := new(big.Int).SetString("3200797265076621797396943577308832679391396371860226890120121432230653785233", 10)
	c1Y, _ := new(big.Int).SetString("5210110328792812562066091196399294499414608384227631465547758111507815530790", 10)
	c2X, _ := new(big.Int).SetString("14353965765711180631440746432124851641123026187756655584132953629432908500962", 10)
	c2Y, _ := new(big.Int).SetString("18899802722931794583798498860596714297548149427767678529077963923612627261516", 10)

	assignments := &testVerifyDecryptionProofCircuit{
		PubKey: twistededwards.Point{
			X: pubKeyX,
			Y: pubKeyY,
		},
		Ciphertext: Ciphertext{
			C1: twistededwards.Point{
				X: c1X,
				Y: c1Y,
			},
			C2: twistededwards.Point{
				X: c2X,
				Y: c2Y,
			},
		},
		Proof: DecryptionProof{
			A1: twistededwards.Point{
				X: mockA1X,
				Y: mockA1Y,
			},
			A2: twistededwards.Point{
				X: mockA2X,
				Y: mockA2Y,
			},
			Z: mockZ,
		},
		Msg: mockMsg,
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testVerifyDecryptionProofCircuit{}, assignments,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
