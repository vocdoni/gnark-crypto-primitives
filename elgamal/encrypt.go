/*
Optimized Fixed-Base Scalar Multiplication

We're implementing a fixed-base scalar multiplication using a windowed method (4-bit window)
to accelerate and reduce constraints in zkSNARK circuits—specifically for multiplying a known
base point G by a scalar.

Instead of computing `[k]G` (scalar times generator) through repeated additions and doublings
in the circuit (which is costly), we precompute a lookup table of multiples of G for all
possible 4-bit combinations.

Then at circuit time, we:

* Split the scalar into 4-bit chunks (nibbles),
* For each nibble, select the corresponding precomputed point from the table,
* Accumulate those points into the result.

This technique has been formally used and benchmarked in tools like Circom, Halo2, Plonky2, and
zkSync's circuit libraries.

References:

* [Zcash Sapling Protocol Spec §5.4.1: Fixed-base scalar mul](https://zips.z.cash/protocol/protocol.pdf)
* [Circomlib: Fixed-base scalar mul implementation](https://github.com/iden3/circomlib/blob/master/circuits/eddsaposeidon.circom#L21)
* [Halo2: Lookup-accelerated scalar multiplication](https://zcash.github.io/halo2/design/proving-system/lookup.html#scalar-multiplication)
* [Plonky2: Efficient fixed-base MSM](https://github.com/mir-protocol/plonky2)
*/

package elgamal

import (
	"math/big"

	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// Encrypt encrypts the message m using the public key pubKey and random k,
// using optimized fixed-base scalar multiplication for [k]*G and [m]*G.
// This should provide significant constraint reduction compared to Encrypt and Encrypt2.
func (z *Ciphertext) Encrypt(api frontend.API, pubKey twistededwards.Point, k, m frontend.Variable) (*Ciphertext, error) {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		return nil, err
	}

	// Validate public key is on curve
	curve.AssertIsOnCurve(pubKey)

	// c1 = [k] * G (using fixed-base optimization)
	z.C1 = FixedBaseScalarMulBN254(api, k)

	// s = [k] * publicKey (variable-base, no optimization available)
	s := curve.ScalarMul(pubKey, k)

	// mPoint = [m] * G (using fixed-base optimization)
	mPoint := FixedBaseScalarMulBN254(api, m)

	// c2 = mPoint + s
	z.C2 = curve.Add(mPoint, s)

	return z, nil
}

// EncryptedZero returns a ciphertext that encrypts the zero message using the
// given public key and random k. It uses optimized fixed-base scalar multiplication
// for [k]*G. The ciphertext is constructed as follows:
//   - C1 = [k] * G (using fixed-base optimization)
//   - S = [k] * publicKey (variable-base)
//   - C2 = zero point (identity point) + S
func EncryptedZero(api frontend.API, pubKey twistededwards.Point, k frontend.Variable) Ciphertext {
	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		panic(err)
	}

	// Validate public key is on curve
	curve.AssertIsOnCurve(pubKey)

	// c1 = [k] * G (using fixed-base optimization)
	c1 := FixedBaseScalarMulBN254(api, k)

	// s = [k] * publicKey (variable-base, no optimization available)
	s := curve.ScalarMul(pubKey, k)

	// mPoint is the identity point (encrypting zero)
	mPoint := twistededwards.Point{X: big.NewInt(0), Y: big.NewInt(1)}

	// c2 = mPoint + s = identity + s = s
	c2 := curve.Add(mPoint, s)

	return Ciphertext{C1: c1, C2: c2}
}
