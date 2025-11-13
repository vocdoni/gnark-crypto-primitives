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
	api.AssertIsEqual(z.IsEqual(api, x), 1)
}

// IsEqual checks if the ciphertext z is equal to x. It returns a variable that
// is 1 if they are equal and 0 otherwise.
func (z *Ciphertext) IsEqual(api frontend.API, x *Ciphertext) frontend.Variable {
	diffs := api.Add(
		api.Sub(z.C1.X, x.C1.X),
		api.Sub(z.C1.Y, x.C1.Y),
		api.Sub(z.C2.X, x.C2.X),
		api.Sub(z.C2.Y, x.C2.Y),
	)
	return api.IsZero(diffs)
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

	finalMsg, multiplier := safeMsgAndMultiplier(api, msg)

	// M = [msg] * G
	M := curve.ScalarMul(G, finalMsg)
	// D = C2 - M = C2 + [-M]
	D := curve.Add(ciphertext.C2, curve.Neg(M))

	// E (Fiat-Shamir challenge) = hFn(PubKey, PubKey, C1, D, A1, A2)
	E := hashPointsToScalar(api, hFn, pubkey, pubkey, ciphertext.C1, D, p.A1, p.A2)

	// zG = [z] * G
	zG := curve.ScalarMul(G, p.Z)
	// eP = [E] * P
	eP := curve.ScalarMul(pubkey, E)
	// A1PlusEP = A1 + eP
	A1PlusEP := curve.Add(p.A1, eP)
	// z·G == A1 + e·P
	assertIsEqualWithMultiplier(api, A1PlusEP.X, zG.X, multiplier)
	assertIsEqualWithMultiplier(api, A1PlusEP.Y, zG.Y, multiplier)

	// zC1 = [z] * C1
	zC1 := curve.ScalarMul(ciphertext.C1, p.Z)
	// eD = [E] * D
	eD := curve.ScalarMul(D, E)
	// A2PlusED = A2 + eD
	A2PlusED := curve.Add(p.A2, eD)
	// z·C1 == A2 + e·D
	assertIsEqualWithMultiplier(api, A2PlusED.X, zC1.X, multiplier)
	assertIsEqualWithMultiplier(api, A2PlusED.Y, zC1.Y, multiplier)
	return nil
}

// safeMsgAndMultiplier returns a final message and a multiplier based on the
// input message. If the message is zero, it returns 1 as the final message
// and 0 as the multiplier to avoid operations with zero. If the message is not
// zero, it returns the original message and 1 as the multiplier.
func safeMsgAndMultiplier(api frontend.API, msg frontend.Variable) (frontend.Variable, frontend.Variable) {
	// If msg is zero, we set it to 1, otherwise we keep it as is.
	finalMsg := api.Select(api.IsZero(msg), frontend.Variable(1), msg)
	// If msg is zero, we set the multiplier to 0, otherwise we set it to 1.
	multiplier := api.Select(api.IsZero(msg), frontend.Variable(0), frontend.Variable(1))
	return finalMsg, multiplier
}

// assertIsEqualWithMultiplier asserts that two variables are equal after
// multiplying them by a given multiplier. This is useful to avoid zero
// multiplications in the circuit, which can lead to issues with zero
// variables in the circuit.
func assertIsEqualWithMultiplier(api frontend.API, x, y, multiplier frontend.Variable) {
	finalX := api.Mul(x, multiplier)
	finalY := api.Mul(y, multiplier)
	api.AssertIsEqual(finalX, finalY)
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

// EncryptedZero returns a ciphertext that encrypts the zero message using the
// given public key and random k. It uses the base point G from the twisted
// Edwards curve to create the ciphertext. The ciphertext is constructed as
// follows:
//   - C1 = [k] * G
//   - S = [k] * publicKey
//   - C2 = zero point (identity point) + S
func EncryptedZero(api frontend.API, pubKey twistededwards.Point, k frontend.Variable) Ciphertext {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		panic(err)
	}
	// get the base point (G)
	base := curve.Params().Base
	G := twistededwards.Point{X: base[0], Y: base[1]}
	// c1 = [k] * G
	c1 := curve.ScalarMul(G, k)
	// s = [k] * publicKey
	s := curve.ScalarMul(pubKey, k)
	mPoint := twistededwards.Point{X: big.NewInt(0), Y: big.NewInt(1)} // zero point
	// c2 = m + s
	c2 := curve.Add(mPoint, s)
	return Ciphertext{C1: c1, C2: c2}
}
