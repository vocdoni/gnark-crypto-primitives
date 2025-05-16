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
// Inputs:
//
//	enabled   : 0 → skip all checks, 1 → fully enforce the rules
//	siblings  : ordered from root (index 0) to leaf (index n-1)
//
// Outputs:
//
//	valid     : 1 ⇔ the proof respects the SMT rules, 0 otherwise
//	levIns[i] : boolean slice (same length as siblings); exactly one entry
//	            is 1 and marks the level whose sibling is the *first* that
//	            differs from zero when walking root→leaf.
//
// Rules (same as circomlib’s smtlevins.circom)
//  1. sibling[n-1] (leaf level) *must* be zero.
//  2. levIns[n-1]  = 1 − isZero[n-2]
//  3. For i = n-2 … 1
//     levIns[i]  = (1 − done[i]) ⋅ (1 − isZero[i-1])
//     done[i-1]  = levIns[i] + done[i]
//  4. levIns[0]    = 1 − done[0]
//  5. Exactly *one* levIns[i] must be 1.
func LevInsFlag(api frontend.API,
	enabled frontend.Variable,
	siblings []frontend.Variable,
) (valid frontend.Variable, levIns []frontend.Variable) {

	n := len(siblings)
	levIns = make([]frontend.Variable, n)

	// 1.  Evaluate   isZero[i]   with ONE hint call
	//     outputs = [flag0…flag{n-1} | inv0…inv{n-1}]
	out, err := api.Compiler().NewHint(MultiInvZeroHint, 2*n, siblings...)
	if err != nil {
		panic(err)
	}

	isZero := out[:n] // flagᵢ = 1 ⟺ siblingᵢ == 0
	inv := out[n:]    // inverse or 0

	// — prove correctness of every (flagᵢ, invᵢ) pair
	for i := range n {
		f := isZero[i]
		s := siblings[i]
		api.AssertIsEqual(api.Mul(s, f), 0)                  // (a) s·f = 0
		api.AssertIsEqual(api.Add(api.Mul(s, inv[i]), f), 1) // (b) s·inv + f = 1
		// booleanity follows from (a)+(b); extra AssertIsBoolean not needed
	}

	if n < 2 { // pathological 1-level tree
		// leaf sibling must be 0 when enabled
		valid = api.Select(enabled, isZero[0], 1)
		return valid, levIns
	}

	// 2.  Build levIns and done  (root → leaf) - identical to Circom
	done := make([]frontend.Variable, n-1)

	// levIns[n-1] = 1 iff parent-sibling non-zero
	levIns[n-1] = api.Sub(1, isZero[n-2])
	done[n-2] = levIns[n-1]

	for i := n - 2; i > 0; i-- {
		levIns[i] = api.Mul(api.Sub(1, done[i]), api.Sub(1, isZero[i-1]))
		done[i-1] = api.Add(levIns[i], done[i])
	}
	levIns[0] = api.Sub(1, done[0])

	// 3.  Validity checks  (leaf sibling zero - Circom: (isZero[n-1]-1)*enabled == 0)
	leafOK := isZero[n-1] // must be 1 when enabled

	// Circom does not add an explicit uniqueness check; keeping it
	// only strengthens the assertion and cannot accept more witnesses.
	sum := frontend.Variable(0)
	for _, v := range levIns {
		sum = api.Add(sum, v)
	}
	uniqOK := api.IsZero(api.Sub(sum, 1)) // Σ levIns == 1
	rawValid := api.Mul(leafOK, uniqOK)

	// If enabled==0 we force valid = 1 (bypass)
	valid = api.Select(enabled, rawValid, 1)
	return
}
