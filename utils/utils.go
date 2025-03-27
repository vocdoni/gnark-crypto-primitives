package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// PackScalarToVar converts a scalar element to a frontend.Variable. This is
// used to convert the scalar elements of a field to frontend.Variable to be
// used in the circuit. The resulting frontend.Variable will be packed with
// in the field of the circuit compiler, so it should be used with care.
func PackScalarToVar[S emulated.FieldParams](api frontend.API, s emulated.Element[S]) (frontend.Variable, error) {
	var fr S
	field, err := emulated.NewField[S](api)
	if err != nil {
		return nil, err
	}
	reduced := field.Reduce(&s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = api.Add(res, api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res, nil
}

// UnpackVarToScalar function converts a frontend.Variable to an emulated
// element of the S field. It is the inverse of PackScalarToVar. The variable
// is transformed into a binary representation and then grouped into limbs of
// nbBits until all limbs are filled or all bits are used. Then the limbs are
// converted to an emulated element of the field. If something goes wrong, an
// error is returned.
func UnpackVarToScalar[S emulated.FieldParams](api frontend.API, v frontend.Variable) (*emulated.Element[S], error) {
	// get field parameters
	var fr S
	nBits := int(fr.BitsPerLimb())
	nLimbs := int(fr.NbLimbs())
	limbs := varToLimbsOfBits(api, v, nLimbs, nBits)
	// convert limbs to emulated element of the field
	field, err := emulated.NewField[S](api)
	if err != nil {
		return nil, err
	}
	return field.NewElement(limbs), nil
}

// StrictCmp function compares a and b and returns:
//
//	1 a != b
//	0 a == b
func StrictCmp(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(api.IsZero(api.Sub(a, b)), 0, 1)
}
