package arbo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// intermediateLeafKey function calculates the intermediate leaf key of the
// path position provided. The leaf key is calculated by hashing the sibling
// and the key provided. The position of the sibling and the key is decided by
// the path position. If the current sibling is not valid, the method will
// return the key provided.
func intermediateLeafKey(api frontend.API, hFn utils.Hasher, ipath, valid, key, sibling frontend.Variable) (frontend.Variable, error) {
	// l, r = path == 1 ? sibling, key : key, sibling
	l, r := api.Select(ipath, sibling, key), api.Select(ipath, key, sibling)
	// intermediateLeafKey = H(l | r)
	intermediateLeafKey, err := hFn(api, l, r)
	if err != nil {
		return 0, err
	}
	// newCurrent = valid == 1 ? intermediateLeafKey : key
	return api.Select(valid, intermediateLeafKey, key), nil
}

// isValid function returns 1 if the the sibling provided is a valid sibling or
// 0 otherwise. To check if the sibling is valid, its leaf key and it must be
// different from the previous leaf key and the previous sibling.
func isValid(api frontend.API, sibling, prevSibling, leaf, prevLeaf frontend.Variable) frontend.Variable {
	cmp1, cmp2 := utils.StrictCmp(api, leaf, prevLeaf), utils.StrictCmp(api, sibling, prevSibling)
	return api.Select(api.Or(cmp1, cmp2), 1, 0)
}

// Legacy version of CheckInclusionProof that uses CheckInclusionProofFlag.
// It asserts that the flag equals 1, indicating a valid inclusion proof.
func CheckInclusionProof(api frontend.API, hFn utils.Hasher, key, value, root frontend.Variable,
	siblings []frontend.Variable,
) error {
	flag := CheckInclusionProofFlag(api, hFn, key, value, root, siblings)
	api.AssertIsEqual(flag, 1)
	return nil
}

// CheckInclusionProofFlag receives the parameters of an inclusion proof of Arbo
// and returns a flag that is 1 if the recalculated root equals the provided root,
// and 0 otherwise.
func CheckInclusionProofFlag(api frontend.API, hFn utils.Hasher, key, value, root frontend.Variable,
	siblings []frontend.Variable,
) frontend.Variable {
	// calculate the path from the provided key to decide which leaf is the correct one
	// in every level of the tree
	path := api.ToBinary(key, len(siblings))
	// calculate the starting leaf key: leafKey = H(key | value | 1)
	leafKey, err := hFn(api, key, value, 1)
	if err != nil {
		// In-circuit error handling: signal failure by returning 0.
		api.Println("failed to compute initial leaf key: " + err.Error())
		return 0
	}
	// Initialize previous values.
	prevKey := leafKey                  // the previously computed leaf key
	prevSibling := frontend.Variable(0) // initial sibling is 0
	// Iterate over the siblings (in reverse order) to rebuild the Merkle root.
	for i := len(siblings) - 1; i >= 0; i-- {
		// Determine if the current sibling is valid by comparing leaf keys.
		valid := isValid(api, siblings[i], prevSibling, leafKey, prevKey)
		// Update previous values.
		prevKey = leafKey
		prevSibling = siblings[i]
		// Compute the intermediate leaf key using the current path bit and validity.
		leafKey, err = intermediateLeafKey(api, hFn, path[i], valid, leafKey, siblings[i])
		if err != nil {
			api.Println("failed to compute intermediate leaf key: " + err.Error())
			return 0
		}
	}
	// Return a flag: 1 if the recomputed leafKey equals the provided root, 0 otherwise.
	return api.IsZero(api.Sub(leafKey, root))
}
