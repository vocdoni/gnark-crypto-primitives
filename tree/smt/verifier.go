package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

/*
InclusionVerifier returns 1 ( valid ) when the pair (key,value) is
contained in the sparse-Merkle tree whose root commitment is root.

Parameters
  - api        – the gnark constraint system API
  - hFn        – Poseidon-based hasher used by the tree
  - root       – public root of the tree (big-endian field element)
  - siblings   – path from root to leaf, packed root→leaf
  - key, value – leaf that must be proven present

Constraints evaluated inside the gadget
 1. A correct leaf commitment is recomputed with hFn.
 2. The path is walked bottom-up, mixing each sibling.
 3. The result must equal the supplied root (enforced through a flag).
 4. All sanity checks coming from the state machine (LevIns, VerifierSM)
    must simultaneously hold.

The caller receives a boolean flag and may decide when or whether to
assert on it.
*/
func InclusionVerifier(
	api frontend.API,
	hFn utils.Hasher,
	root frontend.Variable,
	siblings []frontend.Variable,
	key, value frontend.Variable,
) frontend.Variable {
	return Verifier(
		api, hFn,
		1, // enabled
		root, siblings,
		key, value, 0, // old leaf (unused)
		key, value, 0, // new leaf (same as old for inclusion)
	)
}

/*
ExclusionVerifier proves that key is not present in the tree.

Parameters
  - api              – gnark API
  - hFn              – hash function of the tree
  - root             – public root commitment
  - siblings         – sibling list root→leaf
  - oldKey, oldValue – neighbour leaf that blocks insertion of key
  - isOld0           – 1 when oldKey/oldValue is the implicit zero-leaf
  - key              – key claimed to be absent

Checks performed
 1. The blocking neighbour is indeed on the path.
 2. The new key cannot reuse the neighbour’s key unless the branch is
    empty (isOld0).
 3. The rebuilt root matches the public root.
 4. All LevIns / VerifierSM invariants hold.

Returns 1 on a valid non-membership proof, 0 otherwise.
*/
func ExclusionVerifier(
	api frontend.API,
	hFn utils.Hasher,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, oldValue, isOld0 frontend.Variable,
	key frontend.Variable,
) frontend.Variable {
	return Verifier(
		api, hFn,
		1, // enabled
		root, siblings,
		oldKey, oldValue, isOld0,
		key, 0, 1, // fnc = 1 → exclusion
	)
}

/*
Verifier is the common front-end for both membership (fnc = 0) and
non-membership (fnc = 1) proofs.

Parameters
  - api, hFn           – as above
  - enabled            – 0 skips every check and returns 1
  - root               – public tree root
  - siblings           – packed sibling list
  - oldKey, oldValue   – leaf being deleted / updated
  - isOld0             – 1 when old leaf is implicit-zero
  - key, value         – leaf being inserted / checked
  - fnc                – 0 = inclusion, 1 = exclusion

High-level operation
 1. Compute Poseidon leaf hashes (Hash1).
 2. Delegate to VerifierWithLeafHashFlag to run all constraints.
 3. Bubble the resulting flag back to the caller.
*/
func Verifier(
	api frontend.API,
	hFn utils.Hasher,
	enabled frontend.Variable,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, oldValue, isOld0 frontend.Variable,
	key, value frontend.Variable,
	fnc frontend.Variable,
) frontend.Variable {
	hash1Old := Hash1(api, hFn, oldKey, oldValue)
	hash1New := Hash1(api, hFn, key, value)

	return VerifierWithLeafHashFlag(
		api, hFn,
		enabled, root, siblings,
		oldKey, hash1Old, isOld0,
		key, hash1New, fnc,
	)
}

/*
VerifierWithLeafHash is a thin wrapper that asserts the flag returned by
VerifierWithLeafHashFlag.  Use it when a failing proof must abort the circuit.

Parameters coincide with VerifierWithLeafHashFlag (see below).
*/
func VerifierWithLeafHash(
	api frontend.API,
	hFn utils.Hasher,
	enabled frontend.Variable,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, hash1Old, isOld0 frontend.Variable,
	key, hash1New frontend.Variable,
	fnc frontend.Variable,
) {
	valid := VerifierWithLeafHashFlag(
		api, hFn,
		enabled, root, siblings,
		oldKey, hash1Old, isOld0,
		key, hash1New, fnc,
	)
	api.AssertIsEqual(valid, 1)
}

/*
VerifierWithLeafHashFlag does the heavy lifting.  It rebuilds the root,
executes the LevIns and VerifierSM state machines, prevents illegal key
reuse in updates, and finally compares the computed root with the public
root.  All individual checks are AND-ed and the function returns 1 when
every condition holds, 0 otherwise.

Parameters
  - api, hFn         – gnark API and Poseidon hasher
  - enabled          – 0 bypasses verification (flag = 1)
  - root             – public root commitment
  - siblings         – list of siblings from root to leaf
  - oldKey, hash1Old – existing leaf (for updates / exclusions)
  - isOld0           – 1 when old leaf is implicit zero
  - key, hash1New    – leaf being inserted / checked
  - fnc              – 0 inclusion, 1 exclusion

Constraints combined in the returned flag
 1. Exactly one state (Top/Old/New/Zero) is active on the last level.
 2. LevIns determines the insertion level correctly.
 3. Key-reuse is forbidden when updating an existing leaf.
 4. The path-hash reconstructed bottom-up matches the public root.
*/
func VerifierWithLeafHashFlag(
	api frontend.API,
	hFn utils.Hasher,
	enabled frontend.Variable,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, hash1Old frontend.Variable,
	isOld0 frontend.Variable,
	key, hash1New frontend.Variable,
	fnc frontend.Variable,
) frontend.Variable {
	nLevels := len(siblings)

	// level state machines
	n2bNew := api.ToBinary(key, api.Compiler().FieldBitLen())
	flagLevIns, smtLevIns := LevInsFlag(api, enabled, siblings)

	stTop := make([]frontend.Variable, nLevels)
	stI0 := make([]frontend.Variable, nLevels)
	stIOld := make([]frontend.Variable, nLevels)
	stINew := make([]frontend.Variable, nLevels)
	stNa := make([]frontend.Variable, nLevels)

	for i := range nLevels {
		if i == 0 {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = VerifierSM(api, isOld0, smtLevIns[i], fnc,
				enabled, 0, 0, 0, api.Sub(1, enabled))
		} else {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = VerifierSM(api, isOld0, smtLevIns[i], fnc,
				stTop[i-1], stI0[i-1], stIOld[i-1], stINew[i-1], stNa[i-1])
		}
	}

	sumStates := api.Add(api.Add(api.Add(
		stNa[nLevels-1], stIOld[nLevels-1]),
		stINew[nLevels-1]), stI0[nLevels-1])
	flagStates := IsEqual(api, sumStates, 1)

	// hash path
	levels := make([]frontend.Variable, nLevels)
	for i := nLevels - 1; i >= 0; i-- {
		next := frontend.Variable(0)
		if i < nLevels-1 {
			next = levels[i+1]
		}
		levels[i] = VerifierLevel(api, hFn,
			stTop[i], stIOld[i], stINew[i],
			siblings[i], hash1Old, hash1New,
			n2bNew[i], next)
	}

	// key-reuse guard
	areKeysEqual := IsEqual(api, oldKey, key)
	keyReuseOK := MultiAnd(api, []frontend.Variable{
		fnc,                // fnc == 1 → exclusion
		api.Sub(1, isOld0), // only relevant when old leaf exists
		areKeysEqual,
		enabled,
	})
	flagKeyReuse := IsEqual(api, keyReuseOK, 0)

	// root comparision
	flagRoot := ForceEqualIfEnabledFlag(api, levels[0], root, enabled)

	// combined flag
	return MultiAnd(api, []frontend.Variable{
		flagStates,
		flagKeyReuse,
		flagRoot,
		flagLevIns,
	})
}
