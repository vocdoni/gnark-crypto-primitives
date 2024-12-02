// twistededwards package provides helper circuit functions to transform points
// (x, y) from the TwistedEdwards format to Reduced TwistedEdwards format and
// vice versa, over BabyJubJub curve. These functions are required because
// Gnark uses the Reduced TwistedEdwards formula while Iden3 uses the standard
// TwistedEdwards formula.
//
// Read more about this here: https://github.com/bellesmarta/baby_jubjub
package twistededwards

import "github.com/consensys/gnark/frontend"

var scalingFactor = frontend.Variable("6360561867910373094066688120553762416144456282423235903351243436111059670888")

func FromRTEtoTE(api frontend.API, x, y frontend.Variable) (frontend.Variable, frontend.Variable) {
	// compute negF = -f mod p
	negF := api.Neg(scalingFactor)
	// compute the inverse of negF in the field
	negFInv := api.Inverse(negF)
	// compute xTE = x / (-f)
	xTE := api.Mul(x, negFInv)
	return xTE, y
}

func FromTEtoRTE(api frontend.API, x, y frontend.Variable) (frontend.Variable, frontend.Variable) {
	// compute negF = -f mod p
	negF := api.Neg(scalingFactor)
	// compute xRTE = x * (-f)
	xRTE := api.Mul(x, negF)
	return xRTE, y
}
