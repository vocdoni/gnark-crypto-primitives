package arbo

import "github.com/consensys/gnark/frontend"

type Hash func(frontend.API, ...frontend.Variable) (frontend.Variable, error)

// intermediateLeafKey function calculates the intermediate leaf key of the
// path position provided. The leaf key is calculated by hashing the sibling
// and the key provided. The position of the sibling and the key is decided by
// the path position. If the current sibling is not valid, the method will
// return the key provided.
func intermediateLeafKey(api frontend.API, hFn Hash, ipath, valid, key, sibling frontend.Variable) (frontend.Variable, error) {
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

// replaceFirstPaddedSibling function replaces the first padded sibling with the
// new sibling provided. The function receives the new sibling, the siblings and
// returns the new siblings with the replacement done. It first calculates the
// index of the first padded sibling and then calls the hint function to replace
// it. The hint function should return the new siblings with the replacement
// done. The function ensures that the replacement was done correctly.
func replaceFirstPaddedSibling(api frontend.API, newSibling frontend.Variable, siblings []frontend.Variable) ([]frontend.Variable, error) {
	// the valid siblins are always the first n siblings that are not zero, so
	// we need to iterate through the siblings in reverse order to find the
	// first non-zero sibling and count the number of valid siblings from there,
	// so the index of the last padded sibling is the number of valid siblings
	index := frontend.Variable(0)
	nonZeroFound := frontend.Variable(0)
	for i := len(siblings) - 1; i >= 0; i-- {
		isNotZero := strictCmp(api, siblings[i], 0)
		nonZeroFound = api.Or(nonZeroFound, isNotZero)
		index = api.Add(index, nonZeroFound)
	}
	// call the hint function to replace the sibling with the index to be
	// replaced, the new sibling and the rest of the siblings
	newSiblings, err := api.Compiler().NewHint(replaceSiblingHint, len(siblings),
		append([]frontend.Variable{newSibling, index}, siblings...)...)
	if err != nil {
		return nil, err
	}
	// check that the hint successfully replaced the first padded sibling
	newSiblingFound := frontend.Variable(0)
	for i := 0; i < len(newSiblings); i++ {
		correctIndex := api.IsZero(api.Sub(index, frontend.Variable(i)))
		correctSibling := api.IsZero(api.Sub(newSiblings[i], newSibling))
		newSiblingFound = api.Or(newSiblingFound, api.And(correctIndex, correctSibling))
	}
	api.AssertIsEqual(newSiblingFound, 1)
	return newSiblings, nil
}

// CheckInclusionProof receives the parameters of an inclusion proof of Arbo to
// recalculate the root with them and compare it with the provided one,
// verifiying the proof.
func CheckInclusionProof(api frontend.API, hFn Hash, key, value, root frontend.Variable,
	siblings []frontend.Variable,
) error {
	// calculate the path from the provided key to decide which leaf is the
	// correct one in every level of the tree
	path := api.ToBinary(key, len(siblings))
	// calculate the current leaf key to start with it to rebuild the tree
	//   leafKey = H(key | value | 1)
	leafKey, err := hFn(api, key, value, 1)
	if err != nil {
		return err
	}
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
		leafKey, err = intermediateLeafKey(api, hFn, path[i], valid, leafKey, siblings[i])
		if err != nil {
			return err
		}
	}
	api.AssertIsEqual(leafKey, root)
	return nil
}

// CheckAdditionProof method proves that the addition of a new key-value pair
// to the tree is valid. It gets the root (old root), the key-value pair of the
// first sibling of the new key-value pair (the old leaf key), and the rest of
// the siblings to check. It also gets the root after including the new
// key-value pair (the new leaf key) and the new key-value pair itself. It
// includes the old leaf key as a sibling of the new leaf key and verifies the
// proof of the new root. In this way, it ensures that the addition of the new
// key-value pair is valid by checking the state of the tree before and after
// the addition.
func CheckAdditionProof(api frontend.API, hFn Hash, key, value, root, oldKey, oldValue,
	oldRoot frontend.Variable, siblings []frontend.Variable,
) error {
	// check that the old proof is valid
	if err := CheckInclusionProof(api, hFn, oldKey, oldValue, oldRoot, siblings); err != nil {
		return err
	}
	// calculate the old leaf key (as new sibling)
	newLeafKey, err := hFn(api, oldKey, oldValue, 1)
	if err != nil {
		return err
	}
	// include the old leaf key as a sibling of the new leaf key
	newSiblings, err := replaceFirstPaddedSibling(api, newLeafKey, siblings)
	if err != nil {
		return err
	}
	// verify the proof of the new leaf key
	return CheckInclusionProof(api, hFn, key, value, root, newSiblings)
}
