package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// PackScalarToVar converts a scalar element to a frontend.Variable. This is
// used to convert the scalar elements of a field to frontend.Variable to be
// used in the circuit. The resulting frontend.Variable will be packed with
// in the field of the circuit compiler, so it should be used with care.
func PackScalarToVar[S emulated.FieldParams](api frontend.API, s *emulated.Element[S]) (frontend.Variable, error) {
	var fr S
	field, err := emulated.NewField[S](api)
	if err != nil {
		return nil, err
	}
	reduced := field.Reduce(s)
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
	limbs := make([]frontend.Variable, nLimbs)
	// get binary representation of the variable
	vBin := bits.ToBinary(api, v, bits.WithNbDigits(nBits*nLimbs))
	// group bits into limbs of nbBits until fill all limbs or all bits
	for i := 0; i < nLimbs; i++ {
		g := vBin[i*nBits : (i+1)*nBits]
		limbs[i] = bits.FromBinary(api, g)
	}
	// convert limbs to emulated element of the field
	field, err := emulated.NewField[S](api)
	if err != nil {
		return nil, err
	}
	return field.NewElement(limbs), nil
}

// ElemToU8 converts a field element to a slice of uint8 by converting each
// limb to a slice of uint8 and concatenating them.
func ElemToU8[T emulated.FieldParams](api frontend.API, elem emulated.Element[T]) ([]uints.U8, error) {
	bf, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	// convert each limb to []uint8
	var res []uints.U8
	for _, limb := range elem.Limbs {
		bLimb := bf.ValueOf(limb)
		for _, b := range bLimb {
			res = append(res, b)
		}
	}
	return res, nil
}

// U8ToVar converts a slice of uint8 to a variable by multiplying the current
// result by 256 and adding the next byte, starting from the most significant
// byte.
func U8ToVar(api frontend.API, u8 []uints.U8) (frontend.Variable, error) {
	res := frontend.Variable(0)
	b := frontend.Variable(256)
	// convert each byte to a variable and sum them
	for i := 0; i < len(u8); i++ {
		res = api.Mul(res, b)
		res = api.Add(res, u8[i].Val)
	}
	return res, nil
}

// SwapEndianness swaps the endianness of a slice of uint8 by reversing it.
func SwapEndianness(u8 []uints.U8) []uints.U8 {
	var swap []uints.U8
	for i := len(u8) - 1; i >= 0; i-- {
		swap = append(swap, u8[i])
	}
	return swap
}

// StrictCmp function compares a and b and returns:
//
//	1 a != b
//	0 a == b
func StrictCmp(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(api.IsZero(api.Sub(a, b)), 0, 1)
}
