package arbo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

// leafValueKey returns the encoded childless leaf value for the key-value pair
// provided, hashing it with the predefined hashing function 'H':
//
//	newLeafValue = H(key | value | 1)
func leafValueKey(api frontend.API, key, value frontend.Variable) frontend.Variable {
	return poseidon.Hash(api, key, value, 1)
}

// intermediateLeafKey returns the encoded intermediate leaf value for the
// key-value pair provided, hashing it with the predefined hashing function 'H':
//
//	intermediateLeafValue = H(l | r)
func intermediateLeafKey(api frontend.API, l, r frontend.Variable) frontend.Variable {
	return poseidon.Hash(api, l, r)
}

// switcher returns the l and r parameters swiped if sel is 1, else returns it
// in the same position:
//
//	switcher(1, l, r) == r, l
//	switcher(0, l, r) == l, r
func switcher(api frontend.API, sel, l, r frontend.Variable) (outL, outR frontend.Variable) {
	// aux <== (R-L)*sel;
	aux := api.Mul(api.Sub(r, l), sel)
	// outL <==  aux + L;
	outL = api.Add(aux, l)
	// outR <== -aux + R;
	outR = api.Sub(r, aux)
	return
}

// calcRoot iterates over valid siblings recursively calculating the root hash
// with the intermediate leaf keys. To do that, it requires the key path in the
// tree and the map of valid siblings.
func calcRoot(api frontend.API, current frontend.Variable, path, valid, siblings []frontend.Variable) frontend.Variable {
	i := len(siblings) - 1
	l, r := switcher(api, path[i], current, siblings[i])
	hash := intermediateLeafKey(api, l, r)
	newCurrent, _ := switcher(api, valid[i], current, hash)
	if i == 0 {
		return newCurrent
	}
	return calcRoot(api, newCurrent, path[:i], valid[:i], siblings[:i])
}

// CheckProof receives the parameters of a proof of Arbo to recalculate the
// root with them and compare it with the provided one, verifiying the proof.
func CheckProof(api frontend.API, key, value, root, nsiblings frontend.Variable, siblings []frontend.Variable) error {
	// ensure that the number of valid siblings are less or equal to the number
	// of provided siblings
	api.AssertIsLessOrEqual(nsiblings, len(siblings))
	// call to ValidSiblings that creates a map of valid siblings
	valid, err := api.NewHint(ValidSiblings, len(siblings), nsiblings)
	if err != nil {
		return err
	}
	
	// calculta the path from the provided key to decide which leaf is the
	// correct one in every level of the tree
	path := api.ToBinary(key, api.Compiler().FieldBitLen())
	// calculate the value leaf to start with it to rebuild the tree
	firstLevel := leafValueKey(api, key, value)
	// calculate the root and compare it with the provided one
	api.AssertIsEqual(calcRoot(api, firstLevel, path, valid, siblings), root)
	return nil
}
