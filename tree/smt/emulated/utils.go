package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func IsEqual[T emulated.FieldParams](field *emulated.Field[T], a, b *emulated.Element[T]) frontend.Variable {
	return field.IsZero(field.Sub(a, b))
}

func ForceEqualIfEnabled[T emulated.FieldParams](field *emulated.Field[T], a, b *emulated.Element[T], enabled frontend.Variable) {
	c := field.Select(enabled, a, b)
	field.AssertIsEqual(c, b)
}

// Switcher is [out1, out2] = sel ? [r, l] : [l, r]
func Switcher[T emulated.FieldParams](field *emulated.Field[T], sel frontend.Variable, l, r *emulated.Element[T]) (*emulated.Element[T], *emulated.Element[T]) {
	return field.Select(sel, r, l), field.Select(sel, l, r)
}

// mux2 is (out = as ? a : bs ? b : 0)
func mux2[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], as, bs frontend.Variable, a, b *emulated.Element[T]) *emulated.Element[T] {
	sel := api.FromBinary(as, bs)
	zero := emulated.ValueOf[T](0)
	return field.Mux(sel, &zero, a, b, a)
}

// mux3 is (out = as ? a : bs ? b : cs ? c : 0)
func mux3[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], as, bs, cs frontend.Variable, a, b, c *emulated.Element[T]) *emulated.Element[T] {
	sel := api.FromBinary(as, bs, cs)
	zero := emulated.ValueOf[T](0)
	return field.Mux(sel, &zero, a, b, a, c, a, b, a)
}
