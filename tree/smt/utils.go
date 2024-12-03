package smt

import (
	"github.com/consensys/gnark/frontend"
)

func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func ForceEqualIfEnabled(api frontend.API, a, b, enabled frontend.Variable) {
	c := api.IsZero(api.Sub(a, b))
	api.AssertIsEqual(api.Mul(api.Sub(1, c), enabled), 0)
}

func MultiAnd(api frontend.API, in []frontend.Variable) frontend.Variable {
	out := frontend.Variable(1)
	for i := 0; i < len(in); i++ {
		out = api.And(out, in[i])
	}
	return out
}

func Switcher(api frontend.API, sel, l, r frontend.Variable) (frontend.Variable, frontend.Variable) {
	aux := api.Mul(api.Sub(r, l), sel)

	outL := api.Add(aux, l)
	outR := api.Sub(r, aux)

	return outL, outR
}
