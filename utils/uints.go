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

// U8ToElem converts a slice of uint8 to a field element. It's the inverse
// operation of ElemToU8, reconstructing an emulated field element from a byte slice.
func U8ToElem[T emulated.FieldParams](api frontend.API, u8s []uints.U8) (emulated.Element[T], error) {
	// Create new field for the element
	field, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	// Get field parameters
	var fr T
	nbLimbs := int(fr.NbLimbs())
	bytesPerLimb := 8 // Each U64 limb is 8 bytes

	// Ensure we have enough bytes, padding if necessary
	totalBytes := nbLimbs * bytesPerLimb
	if len(u8s) < totalBytes {
		paddedU8s := make([]uints.U8, totalBytes)
		copy(paddedU8s, u8s)
		u8s = paddedU8s
	} else if len(u8s) > totalBytes {
		u8s = u8s[:totalBytes]
	}

	// Create limbs for the element
	limbs := make([]frontend.Variable, nbLimbs)

	// Process each limb
	for i := range nbLimbs {
		offset := i * bytesPerLimb

		// For each byte in the limb
		value := frontend.Variable(0)
		for j := 0; j < bytesPerLimb; j++ {
			// Get the multiplier for this byte position (256^position)
			multiplier := frontend.Variable(1)
			for k := 0; k < j; k++ {
				multiplier = api.Mul(multiplier, 256)
			}

			// Add this byte's contribution to the limb value
			contribution := api.Mul(u8s[offset+j].Val, multiplier)
			value = api.Add(value, contribution)
		}

		limbs[i] = value
	}

	// Create and return the element with the constructed limbs
	return *field.NewElement(limbs), nil
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
func varToLimbsOfBits(api frontend.API, v frontend.Variable, nLimbs, nbBits int) []frontend.Variable {
	limbs := make([]frontend.Variable, nLimbs)
	// get binary representation of the variable
	vBin := bits.ToBinary(api, v, bits.WithNbDigits(nbBits*nLimbs))
	// group bits into limbs of nbBits until fill all limbs or all bits
	for i := range nLimbs {
		g := vBin[i*nbBits : (i+1)*nbBits]
		limbs[i] = bits.FromBinary(api, g)
	}
	return limbs
}
