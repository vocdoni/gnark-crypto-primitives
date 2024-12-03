package emulated

import (
	"github.com/consensys/gnark/std/math/emulated"

	poseidon "github.com/mdehoog/poseidon/circuits/poseidon/emulated"
)

// based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smthash_poseidon.circom

func Hash1[T emulated.FieldParams](field *emulated.Field[T], key, value *emulated.Element[T]) *emulated.Element[T] {
	one := emulated.ValueOf[T](1)
	inputs := []*emulated.Element[T]{key, value, &one}
	return poseidon.Hash(field, inputs)
}

func Hash2[T emulated.FieldParams](field *emulated.Field[T], l, r *emulated.Element[T]) *emulated.Element[T] {
	inputs := []*emulated.Element[T]{l, r}
	return poseidon.Hash(field, inputs)
}
