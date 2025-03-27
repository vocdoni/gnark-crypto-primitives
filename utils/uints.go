package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

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
	for i := range u8 {
		res = api.Mul(res, b)
		res = api.Add(res, u8[i].Val)
	}
	return res, nil
}

// VarToU8 converts a variable to a slice of uint8. First, the variable is
// converted to a slice of uint64, then each uint64 is converted to a slice
// of uint8 and concatenated. Finally, the endianness is swapped to match the
// expected endianness of the slice of uint8.
func VarToU8(api frontend.API, v frontend.Variable) ([]uints.U8, error) {
	limbs := varToLimbsOfBits(api, v, 4, 64)
	// convert each limb to []uint8
	bf, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	var u8 []uints.U8
	for _, limb := range limbs {
		bLimb := bf.ValueOf(limb)
		for _, b := range bLimb {
			u8 = append(u8, b)
		}
	}
	return SwapEndianness(u8), nil
}

// SwapEndianness swaps the endianness of a slice of uint8 by reversing it.
func SwapEndianness(u8 []uints.U8) []uints.U8 {
	var swap []uints.U8
	for i := len(u8) - 1; i >= 0; i-- {
		swap = append(swap, u8[i])
	}
	return swap
}

// varToLimbsOfBits function converts a variable to a slice of variables, each
// representing a limb of nbBits. The variable is first converted to a binary
// representation, then the bits are grouped into limbs of nbBits until all
// limbs are filled or all bits are used.
func varToLimbsOfBits(api frontend.API, v frontend.Variable, nLimbs, nBits int) []frontend.Variable {
	limbs := make([]frontend.Variable, nLimbs)
	// get binary representation of the variable
	vBin := bits.ToBinary(api, v, bits.WithNbDigits(nBits*nLimbs))
	// group bits into limbs of nbBits until fill all limbs or all bits
	for i := range nLimbs {
		g := vBin[i*nBits : (i+1)*nBits]
		limbs[i] = bits.FromBinary(api, g)
	}
	return limbs
}
