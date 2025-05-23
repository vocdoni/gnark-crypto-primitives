package elgamal

import (
	"math/big"

	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
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
