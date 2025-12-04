package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func VerifierLevel[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], stTop, stIOld, stINew frontend.Variable, sibling, old1leaf, new1leaf *emulated.Element[T], lrbit frontend.Variable, child *emulated.Element[T]) (root *emulated.Element[T]) {
	proofHashL, proofHashR := Switcher(field, lrbit, child, sibling)
	proofHash := Hash2(field, proofHashL, proofHashR)
	root = mux3(api, field, stTop, stIOld, stINew, proofHash, old1leaf, new1leaf)
	return root
}
