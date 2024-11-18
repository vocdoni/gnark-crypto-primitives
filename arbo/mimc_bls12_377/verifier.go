package arbo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// intermediateLeafKey function calculates the intermediate leaf key of the
// path position provided. The leaf key is calculated by hashing the sibling
// and the key provided. The position of the sibling and the key is decided by
// the path position. If the current sibling is not valid, the method will
// return the key provided.
func intermediateLeafKey(api frontend.API, ipath, valid, key, sibling frontend.Variable) (frontend.Variable, error) {
	// l, r = path == 1 ? sibling, key : key, sibling
	l, r := api.Select(ipath, sibling, key), api.Select(ipath, key, sibling)
	// intermediateLeafKey = H(l | r)
	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, err
	}
	hash.Write(l, r)
	intermediateLeafKey := hash.Sum()
	// newCurrent = valid == 1 ? intermediateLeafKey : key
	return api.Select(valid, intermediateLeafKey, key), nil
}

// strictCmp function compares a and b and returns:
//
//	1 a != b
//	0 a == b
func strictCmp(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(api.IsZero(api.Sub(a, b)), 0, 1)
}

// isValid function returns 1 if the the sibling provided is a valid sibling or
// 0 otherwise. To check if the sibling is valid, its leaf key and it must be
// different from the previous leaf key and the previous sibling.
func isValid(api frontend.API, sibling, prevSibling, leaf, prevLeaf frontend.Variable) frontend.Variable {
	cmp1, cmp2 := strictCmp(api, leaf, prevLeaf), strictCmp(api, sibling, prevSibling)
	return api.Select(api.Or(cmp1, cmp2), 1, 0)
}

// CheckProof receives the parameters of a proof of Arbo to recalculate the
// root with them and compare it with the provided one, verifiying the proof.
func CheckProof(api frontend.API, key, value, root frontend.Variable, siblings []frontend.Variable) error {
	// calculate the path from the provided key to decide which leaf is the
	// correct one in every level of the tree
	path := api.ToBinary(key, len(siblings))
	// calculate the current leaf key to start with it to rebuild the tree
	//   leafKey = H(key | value | 1)
	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash.Write(key, value, 1)
	leafKey := hash.Sum()
	// calculate the root iterating through the siblings in inverse order,
	// calculating the intermediate leaf key based on the path and the validity
	// of the current sibling
	prevKey := leafKey                  // init prevKey with computed leafKey
	prevSibling := frontend.Variable(0) // init prevSibling with 0
	for i := len(siblings) - 1; i >= 0; i-- {
		// check if the sibling is valid
		valid := isValid(api, siblings[i], prevSibling, leafKey, prevKey)
		prevKey = leafKey         // update prevKey to the lastKey
		prevSibling = siblings[i] // update prevSibling to the current sibling
		// compute the intermediate leaf key and update the lastKey
		leafKey, err = intermediateLeafKey(api, path[i], valid, leafKey, siblings[i])
		if err != nil {
			return err
		}
	}
	api.AssertIsEqual(leafKey, root)
	return nil
}
