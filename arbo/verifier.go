package arbo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

// prevLevel function calculates the previous level of the merkle tree given the
// current leaf, the current path bit of the leaf, the validity of the sibling
// and the sibling itself.
func prevLevel(api frontend.API, leaf, ipath, valid, sibling frontend.Variable) frontend.Variable {
	// l, r = path == 1 ? sibling, current : current, sibling
	l, r := api.Select(ipath, sibling, leaf), api.Select(ipath, leaf, sibling)
	// intermediateLeafKey = H(l | r)
	intermediateLeafKey := poseidon.Hash(api, l, r)
	// newCurrent = valid == 1 ? current : intermediateLeafKey
	return api.Select(valid, intermediateLeafKey, leaf)
}

// strictCmp function compares a and b and returns:
//
//	1 a != b
//	0 a == b
func strictCmp(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(api.IsZero(api.Sub(a, b)), 0, 1)
}

// isValid function returns 1 if the the sibling provided is a valid sibling or
// 0 otherwise. To check if the sibling is valid, its leaf value and it must be
// different from the previous leaf value and the previous sibling.
func isValid(api frontend.API, sibling, prevSibling, leaf, prevLeaf frontend.Variable) frontend.Variable {
	cmp1, cmp2 := strictCmp(api, leaf, prevLeaf), strictCmp(api, sibling, prevSibling)
	return api.Select(api.Or(cmp1, cmp2), 1, 0)
}

// CheckProof receives the parameters of a proof of Arbo to recalculate the
// root with them and compare it with the provided one, verifiying the proof.
func CheckProof(api frontend.API, key, value, root frontend.Variable, siblings []frontend.Variable) error {
	// calculate the path from the provided key to decide which leaf is the
	// correct one in every level of the tree
	path := api.ToBinary(key, api.Compiler().FieldBitLen())
	// calculate the value leaf to start with it to rebuild the tree
	//   leafValue = H(key | value | 1)
	leafValue := poseidon.Hash(api, key, value, 1)
	// calculate the root and compare it with the provided one
	prevLeaf := leafValue
	currentLeaf := leafValue
	prevSibling := frontend.Variable(0)
	for i := len(siblings) - 1; i >= 0; i-- {
		// check if the sibling is valid
		valid := isValid(api, siblings[i], prevSibling, currentLeaf, prevLeaf)
		prevLeaf = currentLeaf
		prevSibling = siblings[i]
		// compute the next leaf value
		currentLeaf = prevLevel(api, currentLeaf, path[i], valid, siblings[i])
	}
	api.AssertIsEqual(currentLeaf, root)
	return nil
}
