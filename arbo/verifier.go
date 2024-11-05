package arbo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
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

// validSiblings function creates a binary map with the slots where a valid
// sibling is located in the siblings list. This function helps to skip
// unnecessary iterations when walking through the merkle tree.
func validSiblings(api frontend.API, siblings []frontend.Variable, nsibling frontend.Variable) []frontend.Variable {
	valid := make([]frontend.Variable, len(siblings))
	for i := 0; i < len(siblings); i++ {
		valid[i] = cmp.IsLess(api, frontend.Variable(i), nsibling)
	}
	return valid
}

// CheckProof receives the parameters of a proof of Arbo to recalculate the
// root with them and compare it with the provided one, verifiying the proof.
func CheckProof(api frontend.API, key, value, root, nsiblings frontend.Variable, siblings []frontend.Variable) error {
	// ensure that the number of valid siblings are less or equal to the number
	// of provided siblings
	api.AssertIsLessOrEqual(nsiblings, len(siblings))
	// get a map with the valid siblings
	valid := validSiblings(api, siblings, nsiblings)
	// calculate the path from the provided key to decide which leaf is the
	// correct one in every level of the tree
	path := api.ToBinary(key, api.Compiler().FieldBitLen())
	// calculate the value leaf to start with it to rebuild the tree
	//   leafValue = H(key | value | 1)
	leafValue := poseidon.Hash(api, key, value, 1)
	// calculate the root and compare it with the provided one
	currentLevel := leafValue
	for i := len(siblings) - 1; i >= 0; i-- {
		currentLevel = prevLevel(api, currentLevel, path[i], valid[i], siblings[i])
	}
	api.AssertIsEqual(currentLevel, root)
	return nil
}
