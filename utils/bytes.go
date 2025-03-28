package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Bytes is a slice of uint8, an abstraction to handle byte slices in the
// circuit.
type Bytes []uints.U8

func (a Bytes) AssertIsEqual(api frontend.API, b Bytes) {
	api.AssertIsEqual(a.IsEqual(api, b), 1)
}

// IsEqual compares two byte slices and returns 1 if they are equal or 0 if
// they are different. It compares each byte of the slices and sums the number
// of differences. If the number of differences is 0, the slices are equal.
func (a Bytes) IsEqual(api frontend.API, b Bytes) frontend.Variable {
	if len(a) != len(b) {
		return 0
	}
	diffBytes := frontend.Variable(0)
	for i := range a {
		diffBytes = api.Add(diffBytes, StrictCmp(api, a[i].Val, b[i].Val))
	}
	return api.IsZero(diffBytes)
}

// ToVar converts a byte slice to a variable using the U8ToVar function.
func (b Bytes) ToVar(api frontend.API) (frontend.Variable, error) {
	return U8ToVar(api, b)
}

// Values returns the values of the byte slice as a slice of frontend.Variable.
func (b Bytes) Values() []frontend.Variable {
	values := make([]frontend.Variable, len(b))
	for i, u8 := range b {
		values[i] = u8.Val
	}
	return values
}

// BytesFromElement converts an emulated element to a byte slice using the
// ElemToU8 function.
func BytesFromElement[T emulated.FieldParams](api frontend.API, e emulated.Element[T]) (Bytes, error) {
	return ElemToU8(api, e)
}

// BytesFromVariable converts a variable to a byte slice using the VarToU8
// function.
func BytesFromVariable(api frontend.API, v frontend.Variable) (Bytes, error) {
	return VarToU8(api, v)
}

// BytesFromBigInt converts a big.Int to a byte slice with a fixed length using
// the BytesFromBigInt function. It is useful to convert a big.Int to a byte
// slice with a fixed length to be used in the circuit.
func BytesFromBigInt(b *big.Int, fixedLen int) Bytes {
	bytes := b.Bytes()
	if len(bytes) > fixedLen {
		bytes = bytes[:fixedLen]
	}
	u8 := make([]uints.U8, fixedLen)
	for i, b := range bytes {
		u8[i] = uints.U8{Val: frontend.Variable(b)}
	}
	return u8
}

// BytesFromString converts a string to a byte slice with a fixed length using
// the BytesFromBigInt function. It is useful to convert a string to a byte
// slice with a fixed length to be used in the circuit.
func BytesFromString(s string, fixexLen int) Bytes {
	return BytesFromBigInt(new(big.Int).SetBytes([]byte(s)), fixexLen)
}
