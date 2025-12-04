package smt

import "github.com/consensys/gnark/frontend"

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessorsm.circom

func ProcessorSM(api frontend.API, xor, is0, levIns, fnc0, prevTop, prevOld0, prevBot, prevNew1, prevNa, prevUpd frontend.Variable) (stTop, stOld0, stBot, stNew1, stNa, stUpd frontend.Variable) {
	aux1 := api.Mul(prevTop, levIns)
	aux2 := api.Mul(aux1, fnc0)
	stTop = api.Sub(prevTop, aux1)
	stOld0 = api.Mul(aux2, is0)
	stNew1 = api.Mul(api.Add(api.Sub(aux2, stOld0), prevBot), xor)
	stBot = api.Mul(api.Sub(1, xor), api.Add(api.Sub(aux2, stOld0), prevBot))
	stUpd = api.Sub(aux1, aux2)
	stNa = api.Add(api.Add(api.Add(prevNew1, prevOld0), prevNa), prevUpd)
	return stTop, stOld0, stBot, stNew1, stNa, stUpd
}
