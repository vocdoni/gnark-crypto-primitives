// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package mimc

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

func constantsToField[T emulated.FieldParams](constants []big.Int) []emulated.Element[T] {
	res := make([]emulated.Element[T], len(constants))
	for i := range constants {
		res[i] = emulated.ValueOf[T](constants[i])
	}

	return []emulated.Element[T]{}
}

// -------------------------------------------------------------------------------------------------
// encryptions functions

func pow5[T emulated.FieldParams](field *emulated.Field[T], x emulated.Element[T]) emulated.Element[T] {
	r := field.Mul(&x, &x)
	r = field.Mul(r, r)
	return *field.Mul(r, &x)
}

func pow7[T emulated.FieldParams](field *emulated.Field[T], x emulated.Element[T]) emulated.Element[T] {
	t := field.Mul(&x, &x)
	r := field.Mul(t, t)
	r = field.Mul(r, t)
	return *field.Mul(r, &x)
}

func pow17[T emulated.FieldParams](field *emulated.Field[T], x emulated.Element[T]) emulated.Element[T] {
	r := field.Mul(&x, &x)
	r = field.Mul(r, r)
	r = field.Mul(r, r)
	r = field.Mul(r, r)
	return *field.Mul(r, &x)
}

// encryptPow5 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow5[T emulated.FieldParams](h MiMC[T], m emulated.Element[T]) emulated.Element[T] {
	x := m
	for i := 0; i < len(h.params); i++ {
		sum := h.field.Add(&h.h, &x)
		x = pow5(h.field, *h.field.Add(sum, &h.params[i]))
	}
	return *h.field.Add(&x, &h.h)
}

// encryptPow7 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow7[T emulated.FieldParams](h MiMC[T], m emulated.Element[T]) emulated.Element[T] {
	x := m
	for i := 0; i < len(h.params); i++ {
		sum := h.field.Add(&h.h, &x)
		x = pow7(h.field, *h.field.Add(sum, &h.params[i]))
	}
	return *h.field.Add(&x, &h.h)
}

// encryptPow17 of a mimc run expressed as r1cs
// m is the message, k the key
func encryptPow17[T emulated.FieldParams](h MiMC[T], m emulated.Element[T]) emulated.Element[T] {
	x := m
	for i := 0; i < len(h.params); i++ {
		// res = (res+key+c)**17
		sum := h.field.Add(&h.h, &x)
		x = pow17(h.field, *h.field.Add(sum, &h.params[i]))
	}
	return *h.field.Add(&x, &h.h)

}
