package smt

import (
	"github.com/consensys/gnark/frontend"
)

func VerifierLevel(api frontend.API, stTop, stIOld, stINew, sibling, old1leaf, new1leaf, lrbit, child frontend.Variable) (root frontend.Variable) {
	proofHashL, proofHashR := Switcher(api, lrbit, child, sibling)
	proofHash := Hash2(api, proofHashL, proofHashR)
	root = api.Add(api.Add(api.Mul(proofHash, stTop), api.Mul(old1leaf, stIOld)), api.Mul(new1leaf, stINew))
	return
}
