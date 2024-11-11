// twistededwards package provides helper functions to transform points (x, y)
// from TwistedEdwards to Reduced TwistedEdwards and vice versa. These functions
// are required because Gnark uses the Reduced TwistedEdwards formula while
// Iden3 uses the standard TwistedEdwards formula.
// See https://github.com/bellesmarta/baby_jubjub for more information.
package twistededwards

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var scalingFactor, _ = new(big.Int).SetString("6360561867910373094066688120553762416144456282423235903351243436111059670888", 10)

type Point struct {
	X, Y *big.Int
}

// Convert Reduced TwistedEdwards x' to TwistedEdwards:
//
//	x = x'/(-f)
//	y' = y
func (p *Point) FromRTEtoTE() *Point {
	// Step 1: Convert scalingFactor to fr.Element (mod p)
	var f fr.Element
	f.SetBigInt(scalingFactor) // f = scalingFactor mod p

	// Step 2: Compute negF = -f mod p
	var negF fr.Element
	negF.Neg(&f) // negF = -f mod p

	// Step 3: Compute the inverse of negF in the field
	var negFInv fr.Element
	negFInv.Inverse(&negF) // negFInv = (-f)^{-1} mod p

	xTE := new(fr.Element)
	xTE.SetBigInt(p.X)
	// Step 4: Multiply g.inner.X by negFInv to get xTE
	xRTE := new(fr.Element)
	xRTE.Mul(xTE, &negFInv) // xTE = g.inner.X * negFInv mod p

	// Step 5: Convert xTE and g.inner.Y to *big.Int
	xRTEBigInt := new(big.Int)
	xRTE.BigInt(xRTEBigInt)
	return &Point{
		X: xRTEBigInt, // x = x' / (-f)
		Y: p.Y,        // y' = y
	}
}

// Convert TwistedEdwards to Reduced TwistedEdwards:
//
//	x' = x*(-f)
//	y = y'
func (p *Point) FromTEtoRTE() *Point {
	// Step 1: Convert scalingFactor to fr.Element (mod p)
	var f fr.Element
	f.SetBigInt(scalingFactor) // f = scalingFactor mod p

	// Step 2: Compute negF = -f mod p
	var negF fr.Element
	negF.Neg(&f) // negF = -f mod p

	// Step 4: Multiply g.inner.X by negF to get xTE
	xRTE := new(fr.Element).SetBigInt(p.X)
	xTE := new(fr.Element)
	xTE.Mul(xRTE, &negF) // xTE = g.inner.X * -f mod p

	// Step 5: Convert xTE and g.inner.Y to *big.Int
	xTEBigInt := new(big.Int)
	xTE.BigInt(xTEBigInt)
	return &Point{
		X: xTEBigInt, // x' = x * (-f)
		Y: p.Y,       // y = y'
	}
}
