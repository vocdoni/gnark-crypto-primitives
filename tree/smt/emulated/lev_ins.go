package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smtlevins.circom

func LevIns[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], enabled frontend.Variable, siblings []*emulated.Element[T]) (levIns []frontend.Variable) {
	levels := len(siblings)
	levIns = make([]frontend.Variable, levels)
	done := make([]frontend.Variable, levels-1)

	isZero := make([]frontend.Variable, levels)
	for i := 0; i < levels; i++ {
		isZero[i] = field.IsZero(siblings[i])
	}
	api.AssertIsEqual(api.Mul(api.Sub(isZero[levels-1], 1), enabled), 0)

	levIns[levels-1] = api.Sub(1, isZero[levels-2])
	done[levels-2] = levIns[levels-1]
	for i := levels - 2; i > 0; i-- {
		levIns[i] = api.Mul(api.Sub(1, done[i]), api.Sub(1, isZero[i-1]))
		done[i-1] = api.Add(levIns[i], done[i])
	}
	levIns[0] = api.Sub(1, done[0])
	return levIns
}
