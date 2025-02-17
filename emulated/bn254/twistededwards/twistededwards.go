// twistededwards package provides helper circuit functions to transform points
// (x, y) from the TwistedEdwards format to Reduced TwistedEdwards format and
// vice versa, over BabyJubJub curve. These functions are required because
// Gnark uses the Reduced TwistedEdwards formula while Iden3 uses the standard
// TwistedEdwards formula.
//
// Read more about this here: https://github.com/bellesmarta/baby_jubjub
package twistededwards

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

var (
	scalingFactor         = frontend.Variable("6360561867910373094066688120553762416144456282423235903351243436111059670888")
	emulatedScalingFactor = emulated.Element[sw_bn254.ScalarField]{
		Limbs: []frontend.Variable{7817090900423792488, 8405395627841593623, 3205086078052995447, 1013295966202553675},
	}
)

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

func FromEmulatedRTEtoTE(api frontend.API, x, y emulated.Element[sw_bn254.ScalarField]) (emulated.Element[sw_bn254.ScalarField], emulated.Element[sw_bn254.ScalarField], error) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return emulated.Element[sw_bn254.ScalarField]{}, emulated.Element[sw_bn254.ScalarField]{}, err
	}
	// compute negF = -f mod p
	negF := field.Neg(&emulatedScalingFactor)
	// compute the inverse of negF in the field
	negFInv := field.Inverse(negF)
	// compute xTE = x / (-f)
	xTE := field.Mul(&x, negFInv)
	return *xTE, y, nil
}

func FromEmulatedTEtoRTE(api frontend.API, x, y emulated.Element[sw_bn254.ScalarField]) (emulated.Element[sw_bn254.ScalarField], emulated.Element[sw_bn254.ScalarField], error) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return emulated.Element[sw_bn254.ScalarField]{}, emulated.Element[sw_bn254.ScalarField]{}, err
	}
	// compute negF = -f mod p
	negF := field.Neg(&emulatedScalingFactor)
	// compute xRTE = x * (-f)
	xRTE := field.Mul(&x, negF)
	return *xRTE, y, nil
}
