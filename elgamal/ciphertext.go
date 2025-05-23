package elgamal

import (
	"math/big"

	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

const NumCiphertexts = 8

type Ciphertexts [NumCiphertexts]Ciphertext

func NewCiphertexts() *Ciphertexts {
	cs := &Ciphertexts{}
	for i := range cs {
		cs[i] = *NewCiphertext()
	}
	return cs
}

// Add sets z to the sum x+y and returns z.
//
// Panics if twistededwards curve init fails.
func (cs *Ciphertexts) Add(api frontend.API, x, y *Ciphertexts) *Ciphertexts {
	for i := range cs {
		cs[i].Add(api, &x[i], &y[i])
	}
	return cs
}

// AssertIsEqual fails if any of the fields differ between z and x
func (cs *Ciphertexts) AssertIsEqual(api frontend.API, x *Ciphertexts) {
	for i := range cs {
		cs[i].AssertIsEqual(api, &x[i])
	}
}

// Select if b is true, sets z = i1, else z = i2, and returns z
func (cs *Ciphertexts) Select(api frontend.API, b frontend.Variable, i1 *Ciphertexts, i2 *Ciphertexts) *Ciphertexts {
	for i := range cs {
		cs[i] = *cs[i].Select(api, b, &i1[i], &i2[i])
	}
	return cs
}

// Serialize returns a slice with the C1.X, C1.Y, C2.X, C2.Y in order
func (cs *Ciphertexts) Serialize() []frontend.Variable {
	vars := []frontend.Variable{}
	for _, z := range cs {
		vars = append(vars,
			z.C1.X,
			z.C1.Y,
			z.C2.X,
			z.C2.Y,
		)
	}
	return vars
}

type Ciphertext struct {
	C1, C2 twistededwards.Point
}

func NewCiphertext() *Ciphertext {
	zero := twistededwards.Point{X: big.NewInt(0), Y: big.NewInt(1)}
	return &Ciphertext{C1: zero, C2: zero}
}

// Add sets z to the sum x+y and returns z.
//
// Panics if twistededwards curve init fails.
func (z *Ciphertext) Add(api frontend.API, x, y *Ciphertext) *Ciphertext {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		panic(err)
	}
	for _, p := range []twistededwards.Point{x.C1, x.C2, y.C1, y.C2} {
		curve.AssertIsOnCurve(p)
	}
	z.C1 = curve.Add(x.C1, y.C1)
	z.C2 = curve.Add(x.C2, y.C2)
	return z
}

// Encrypt encrypts the message m using the public key pubKey and random k and
// returns the ciphertext z.
func (z *Ciphertext) Encrypt(api frontend.API, pubKey twistededwards.Point, k, m frontend.Variable) (*Ciphertext, error) {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return nil, err
	}
	// get the base point (G)
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}
	// c1 = [k] * G
	z.C1 = curve.ScalarMul(G, k)
	// s = [k] * publicKey
	s := curve.ScalarMul(pubKey, k)
	// m = [message] * G
	mPoint := curve.ScalarMul(G, m)
	// c2 = m + s
	z.C2 = curve.Add(mPoint, s)
	return z, nil
}

// AssertDecrypt checks if the ciphertext z can be decrypted with privKey
// to the message m. It returns an error if the curve initialization fails.
func (z *Ciphertext) AssertDecrypt(api frontend.API, privKey, m frontend.Variable) error {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return err
	}
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}
	// s = [privKey] * C1
	S := curve.ScalarMul(z.C1, privKey)
	// M = [message] * G
	M := curve.ScalarMul(G, m)
	// M' = C2 - S = C2 + [-S]
	MPrime := curve.Add(z.C2, curve.Neg(S))
	// M' == M
	api.AssertIsEqual(MPrime.X, M.X)
	api.AssertIsEqual(MPrime.Y, M.Y)
	return nil
}

// AssertIsEqual fails if any of the fields differ between z and x
func (z *Ciphertext) AssertIsEqual(api frontend.API, x *Ciphertext) {
	api.AssertIsEqual(z.C1.X, z.C1.X)
	api.AssertIsEqual(z.C1.Y, x.C1.Y)
	api.AssertIsEqual(z.C2.X, x.C2.X)
	api.AssertIsEqual(z.C2.Y, x.C2.Y)
}

// Select if b is true, sets z = i1, else z = i2, and returns z
func (z *Ciphertext) Select(api frontend.API, b frontend.Variable, i1 *Ciphertext, i2 *Ciphertext) *Ciphertext {
	z.C1.X = api.Select(b, i1.C1.X, i2.C1.X)
	z.C1.Y = api.Select(b, i1.C1.Y, i2.C1.Y)
	z.C2.X = api.Select(b, i1.C2.X, i2.C2.X)
	z.C2.Y = api.Select(b, i1.C2.Y, i2.C2.Y)
	return z
}

// Serialize returns a slice with the C1.X, C1.Y, C2.X, C2.Y in order
func (z *Ciphertext) Serialize() []frontend.Variable {
	return []frontend.Variable{
		z.C1.X,
		z.C1.Y,
		z.C2.X,
		z.C2.Y,
	}
}

// DecryptionProof is a non-interactive Chaum–Pedersen proof that C2 – M·G and
// C1 share the same discrete log with respect to P and G.
type DecryptionProof struct {
	A1 twistededwards.Point
	A2 twistededwards.Point
	Z  frontend.Variable
}

// VerifyDecryptionProof checks a Chaum–Pedersen proof of correct decryption.
// It verifies that:
//
//	z·G = A1 + e·P
//	z·C1 = A2 + e·D
//
// where e is the Fiat-Shamir challenge, P is the public key, G is the base
// point, D is the shared secret part, and z is the random scalar used in the
// encryption.
func (p *DecryptionProof) Verify(
	api frontend.API,
	hFn utils.Hasher,
	pubkey twistededwards.Point,
	ciphertext Ciphertext,
	msg frontend.Variable,
) error {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return err
	}
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}

	// M = [msg] * G
	M := curve.ScalarMul(G, msg)
	// D = C2 - M = C2 + [-M]
	D := curve.Add(ciphertext.C2, curve.Neg(M))

	// E (Fiat-Shamir challenge) = hFn(PubKey, PubKey, C1, D, A1, A2)
	E := hashPointsToScalar(api, hFn, pubkey, pubkey, ciphertext.C1, D, p.A1, p.A2)

	// zG = [z] * G
	zG := curve.ScalarMul(G, p.Z)
	// eP = [E] * P
	eP := curve.ScalarMul(pubkey, E)
	// A1PlusEP = A1 + eP
	A1PlusEP := curve.Add(zG, eP)
	// z·G == A1 + e·P
	api.AssertIsEqual(A1PlusEP.X, zG.X)
	api.AssertIsEqual(A1PlusEP.Y, zG.Y)

	// zC1 = [z] * C1
	zC1 := curve.ScalarMul(ciphertext.C1, p.Z)
	// eD = [E] * D
	eD := curve.ScalarMul(D, E)
	// A2PlusED = A2 + eD
	A2PlusED := curve.Add(ciphertext.C1, eD)
	// z·C1 == A2 + e·D
	api.AssertIsEqual(A2PlusED.X, zC1.X)
	api.AssertIsEqual(A2PlusED.Y, zC1.Y)
	return nil
}

// hashPointsToScalar hashes the given points to a scalar using the provided
// hasher function. It concatenates the X and Y coordinates of each point and
// passes them to the hasher function. It is the Fiat-Shamir transformation.
func hashPointsToScalar(api frontend.API, hFn utils.Hasher, points ...twistededwards.Point) frontend.Variable {
	// Hash the points to a scalar
	coords := []frontend.Variable{}
	for _, p := range points {
		coords = append(coords, p.X, p.Y)
	}
	digest, err := hFn(api, coords...)
	if err != nil {
		panic(err)
	}
	return digest
}
