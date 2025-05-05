package smt

import "github.com/consensys/gnark/frontend"

// LevIns finds the level where the oldInsert is done.
// The rules are:
// levIns[i] == 1 if its level and all the child levels have a sibling of 0 and
// the parent level has a sibling != 0.  Considere that the root level always has
// a parent with a sibling != 0.
//
// The last level must always have a sibling of 0. If not, then it cannot be inserted and
// the circuit will assert it.
//
// Based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smtlevins.circom
func LevIns(api frontend.API, enabled frontend.Variable, siblings []frontend.Variable) []frontend.Variable {
	valid, levIns := LevInsFlag(api, enabled, siblings)
	api.AssertIsEqual(valid, 1)
	return levIns
}

// LevInsFlag detects the insertion-level in a Sparse-Merkle-Tree proof.
//
// Inputs -----------------------------------------------------------------
//
//	enabled   : 0 → skip all checks, 1 → fully enforce the rules
//	siblings  : ordered from root (index 0) to leaf (index n-1)
//
// Outputs ----------------------------------------------------------------
//
//	valid     : 1 ⇔ the proof respects the SMT rules, 0 otherwise
//	levIns[i] : boolean slice (same length as siblings); exactly one entry
//	            is 1 and marks the level whose sibling is the *first* that
//	            differs from zero when walking root→leaf.
//
// Rules (same as circomlib’s smtlevins.circom) ---------------------------
//  1. sibling[n-1] (leaf level) *must* be zero.
//  2. levIns[n-1]  = 1 − isZero[n-2]
//  3. For i = n-2 … 1
//     levIns[i]  = (1 − done[i]) ⋅ (1 − isZero[i-1])
//     done[i-1]  = levIns[i] + done[i]
//  4. levIns[0]    = 1 − done[0]
//  5. Exactly *one* levIns[i] must be 1.
func LevInsFlag(
	api frontend.API,
	enabled frontend.Variable,
	siblings []frontend.Variable,
) (valid frontend.Variable, levIns []frontend.Variable) {
	n := len(siblings)
	levIns = make([]frontend.Variable, n)
	if n < 2 { // optional guard: single-level tree
		return api.Select(enabled, 0, 1), levIns
	}

	// 1. isZero[i]
	isZero := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		isZero[i] = api.IsZero(siblings[i])
	}

	// 2–4. build levIns & done (root→leaf)
	done := make([]frontend.Variable, n-1)
	levIns[n-1] = api.Sub(1, isZero[n-2])
	done[n-2] = levIns[n-1]
	for i := n - 2; i > 0; i-- {
		levIns[i] = api.Mul(api.Sub(1, done[i]), api.Sub(1, isZero[i-1]))
		done[i-1] = api.Add(levIns[i], done[i])
	}
	levIns[0] = api.Sub(1, done[0])

	// 5. validity checks
	leafZeroOK := isZero[n-1] // sibling[n-1] == 0
	sum := frontend.Variable(0)
	for _, v := range levIns {
		sum = api.Add(sum, v)
	}
	uniqOK := api.IsZero(api.Sub(sum, 1)) // exactly one level chosen
	rawValid := api.Mul(leafZeroOK, uniqOK)

	// enable switch
	valid = api.Select(enabled, rawValid, 1)
	return valid, levIns
}
