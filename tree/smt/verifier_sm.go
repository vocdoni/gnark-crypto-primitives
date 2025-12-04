package smt

import "github.com/consensys/gnark/frontend"

func VerifierSM(api frontend.API, is0, levIns, fnc, prevTop, prevI0, prevIOld, prevINew, prevNa frontend.Variable) (stTop, stI0, stIOld, stINew, stNa frontend.Variable) {
	aux1 := api.Mul(prevTop, levIns)
	aux2 := api.Mul(aux1, fnc)
	stTop = api.Sub(prevTop, aux1)
	stINew = api.Sub(aux1, aux2)
	stIOld = api.Mul(aux2, api.Sub(1, is0))
	stI0 = api.Mul(aux1, is0)
	stNa = api.Add(prevNa, prevINew, prevIOld, prevI0)
	return stTop, stI0, stIOld, stINew, stNa
}
