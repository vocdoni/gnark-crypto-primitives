package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

func VerifierLevel(api frontend.API, hFn utils.Hasher, stTop, stIOld, stINew, sibling, old1leaf, new1leaf, lrbit, child frontend.Variable) (root frontend.Variable) {
	proofHashL, proofHashR := Switcher(api, lrbit, child, sibling)
	proofHash := Hash2(api, hFn, proofHashL, proofHashR)
	root = api.Add(api.Add(api.Mul(proofHash, stTop), api.Mul(old1leaf, stIOld)), api.Mul(new1leaf, stINew))
	return
}
