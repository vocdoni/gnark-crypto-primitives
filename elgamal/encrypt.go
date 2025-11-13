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
	"sync"

	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecc_tweds "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
)

// fixedBaseTable holds precomputed multiples of the base point G in 4-bit windows.
// Each entry fixedBaseTable[i][v] contains [v * 2^(4*i)] * G.
// Initialized lazily on first use.
var (
	fixedBaseTable     [][][2]*big.Int // each point as [X, Y]
	fixedBaseTableOnce sync.Once
)

// initFixedBaseTable precomputes the base table used for windowed scalar multiplication.
// It supports 252-bit scalars (BabyJubjub on BN254).
// For each window i (0 to 62), it computes points [j * 2^(4*i)] * G for j = 0 to 15.
func initFixedBaseTable() {
	const numWindows = 63 // 252 bits / 4 bits per window = 63 windows
	fixedBaseTable = make([][][2]*big.Int, numWindows)

	// Get the BN254 twisted Edwards curve parameters
	edcurve := edbn254.GetEdwardsCurve()

	// Get base point
	var basePoint edbn254.PointAffine
	basePoint.X.Set(&edcurve.Base.X)
	basePoint.Y.Set(&edcurve.Base.Y)

	// Identity point (0, 1)
	identity := [2]*big.Int{big.NewInt(0), big.NewInt(1)}

	for i := range numWindows {
		table := make([][2]*big.Int, 16) // 0 through 15
		table[0] = identity

		// For window i, compute [j * 2^(4*i)] * G for j = 1 to 15
		// windowMultiplier = 2^(4*i)
		windowMultiplier := new(big.Int).Lsh(big.NewInt(1), uint(4*i))

		for j := 1; j < 16; j++ {
			// scalar = j * 2^(4*i)
			scalar := new(big.Int).Mul(big.NewInt(int64(j)), windowMultiplier)

			// Compute [scalar] * G
			var point edbn254.PointAffine
			point.ScalarMultiplication(&basePoint, scalar)

			// Convert to big.Int
			xBig := new(big.Int)
			yBig := new(big.Int)
			point.X.BigInt(xBig)
			point.Y.BigInt(yBig)

			table[j] = [2]*big.Int{xBig, yBig}
		}
		fixedBaseTable[i] = table
	}
}

// FixedBaseScalarMul performs an optimized scalar multiplication of a secret scalar with a fixed base (G),
// using 4-bit windowing with Lookup2 for efficient selection.
func FixedBaseScalarMul(api frontend.API, scalar frontend.Variable) twistededwards.Point {
	// Initialize table on first use
	fixedBaseTableOnce.Do(initFixedBaseTable)

	curve, err := twistededwards.NewEdCurve(api, ecc_tweds.BN254)
	if err != nil {
		panic(err)
	}

	// Break scalar into 4-bit windows (252 bits total)
	scalarBits := bits.ToBinary(api, scalar, bits.WithNbDigits(252))
	nWindows := len(scalarBits) / 4

	// Result initialized to identity
	res := twistededwards.Point{
		X: 0,
		Y: 1,
	}

	for i := range nWindows {
		// Get 4 bits for this window
		bits4 := scalarBits[i*4 : (i+1)*4]

		// Use Lookup2 for efficient 16-way selection
		table := fixedBaseTable[i]

		// Prepare X coordinates for lookup
		xValues := make([]frontend.Variable, 16)
		yValues := make([]frontend.Variable, 16)
		for j := 0; j < 16; j++ {
			xValues[j] = table[j][0]
			yValues[j] = table[j][1]
		}

		// Use nested Lookup2 for 4-bit (16-way) selection
		// First level: select based on bits [0:1] (4 groups of 4)
		px0 := api.Lookup2(bits4[0], bits4[1], xValues[0], xValues[1], xValues[2], xValues[3])
		px1 := api.Lookup2(bits4[0], bits4[1], xValues[4], xValues[5], xValues[6], xValues[7])
		px2 := api.Lookup2(bits4[0], bits4[1], xValues[8], xValues[9], xValues[10], xValues[11])
		px3 := api.Lookup2(bits4[0], bits4[1], xValues[12], xValues[13], xValues[14], xValues[15])
		// Second level: select based on bits [2:3]
		px := api.Lookup2(bits4[2], bits4[3], px0, px1, px2, px3)

		py0 := api.Lookup2(bits4[0], bits4[1], yValues[0], yValues[1], yValues[2], yValues[3])
		py1 := api.Lookup2(bits4[0], bits4[1], yValues[4], yValues[5], yValues[6], yValues[7])
		py2 := api.Lookup2(bits4[0], bits4[1], yValues[8], yValues[9], yValues[10], yValues[11])
		py3 := api.Lookup2(bits4[0], bits4[1], yValues[12], yValues[13], yValues[14], yValues[15])
		py := api.Lookup2(bits4[2], bits4[3], py0, py1, py2, py3)

		contrib := twistededwards.Point{X: px, Y: py}

		// Note: We skip curve validation here since all precomputed points are valid
		// This saves ~63 constraints per fixed-base multiplication

		// Add contribution to result
		res = curve.Add(res, contrib)
	}

	return res
}

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
	z.C1 = FixedBaseScalarMul(api, k)

	// s = [k] * publicKey (variable-base, no optimization available)
	s := curve.ScalarMul(pubKey, k)

	// mPoint = [m] * G (using fixed-base optimization)
	mPoint := FixedBaseScalarMul(api, m)

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
	c1 := FixedBaseScalarMul(api, k)

	// s = [k] * publicKey (variable-base, no optimization available)
	s := curve.ScalarMul(pubKey, k)

	// mPoint is the identity point (encrypting zero)
	mPoint := twistededwards.Point{X: big.NewInt(0), Y: big.NewInt(1)}

	// c2 = mPoint + s = identity + s = s
	c2 := curve.Add(mPoint, s)

	return Ciphertext{C1: c1, C2: c2}
}
