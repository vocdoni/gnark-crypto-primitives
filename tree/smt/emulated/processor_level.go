package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessorlevel.circom

func ProcessorLevel[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], stTop, stOld0, stBot, stNew1, stUpd frontend.Variable, sibling, old1leaf, new1leaf *emulated.Element[T], newlrbit frontend.Variable, oldChild, newChild *emulated.Element[T]) (oldRoot, newRoot *emulated.Element[T]) {
	oldProofHashL, oldProofHashR := Switcher(field, newlrbit, oldChild, sibling)
	oldProofHash := Hash2(field, oldProofHashL, oldProofHashR)

	am := api.Add(api.Add(stBot, stNew1), stUpd)
	oldRoot = mux2(api, field, am, stTop, old1leaf, oldProofHash)

	am = api.Add(stTop, stBot)
	a := mux2(api, field, am, stNew1, newChild, new1leaf)
	b := mux2(api, field, stTop, stNew1, sibling, old1leaf)
	newProofHashL, newProofHashR := Switcher(field, newlrbit, a, b)
	newProofHash := Hash2(field, newProofHashL, newProofHashR)

	am = api.Add(api.Add(stTop, stBot), stNew1)
	bm := api.Add(stOld0, stUpd)
	newRoot = mux2(api, field, am, bm, newProofHash, new1leaf)
	return
}
