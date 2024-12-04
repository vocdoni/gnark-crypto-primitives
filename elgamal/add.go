package elgamal

import (
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Ciphertext struct {
	C1, C2 twistededwards.Point
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

// AssertIsEqual fails if any of the fields differ between z and x
func (z *Ciphertext) AssertIsEqual(api frontend.API, x *Ciphertext) {
	api.AssertIsEqual(z.C1.X, z.C1.X)
	api.AssertIsEqual(z.C1.Y, x.C1.Y)
	api.AssertIsEqual(z.C2.X, x.C2.X)
	api.AssertIsEqual(z.C2.Y, x.C2.Y)
}
