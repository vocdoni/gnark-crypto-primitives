package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessorlevel.circom

func ProcessorLevel(api frontend.API, hFn utils.Hasher, stTop, stOld0, stBot, stNew1, stUpd, sibling, old1leaf, new1leaf, newlrbit, oldChild, newChild frontend.Variable) (oldRoot, newRoot frontend.Variable) {
	oldProofHashL, oldProofHashR := Switcher(api, newlrbit, oldChild, sibling)
	oldProofHash := Hash2(api, hFn, oldProofHashL, oldProofHashR)

	oldRoot = api.Add(api.Mul(old1leaf, api.Add(api.Add(stBot, stNew1), stUpd)), api.Mul(oldProofHash, stTop))

	newProofHashL, newProofHashR := Switcher(api, newlrbit, api.Add(api.Mul(newChild, api.Add(stTop, stBot)), api.Mul(new1leaf, stNew1)), api.Add(api.Mul(sibling, stTop), api.Mul(old1leaf, stNew1)))
	newProofHash := Hash2(api, hFn, newProofHashL, newProofHashR)

	newRoot = api.Add(api.Mul(newProofHash, api.Add(api.Add(stTop, stBot), stNew1)), api.Mul(new1leaf, api.Add(stOld0, stUpd)))
	return
}
