package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// InclusionVerifier checks that (key,value) is *present* in the Sparse-Merkle-
// Tree whose root is `root`.
// It returns 1 when the proof is valid and 0 otherwise – no assertion
// is fired, so the caller may chain several checks and assert at the end if
// they wish.
func InclusionVerifier(
	api frontend.API,
	hFn utils.Hasher,
	root frontend.Variable,
	siblings []frontend.Variable,
	key, value frontend.Variable,
) frontend.Variable {
	return Verifier(
		api, hFn, 1, root, siblings,
		key, value, 0,
		key, value, 0,
	)
}

// ExclusionVerifier proves that `key` is *absent* from the tree.
// `oldKey‖oldValue` is the neighbour leaf that prevents the key from being
// inserted (see the Iden3 SMT paper, §4.3).
// `isOld0` ≙ 1 when the tree is empty on that branch.
//
// It returns 1 on a correct non-membership proof, 0 otherwise.
func ExclusionVerifier(
	api frontend.API,
	hFn utils.Hasher,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, oldValue, isOld0 frontend.Variable, // witness for the existing leaf
	key frontend.Variable, // the key we claim is absent
) frontend.Variable {
	return Verifier(
		api, hFn, 1, root, siblings,
		oldKey, oldValue, isOld0,
		key, 0, 1,
	)
}

// Verifier is the common entry-point for both inclusion and exclusion proofs.
//
// * **enabled** – set to 0 to bypass all checks (flag will always be 1).
// * **fnc**     – 0 ⇒ inclusion, 1 ⇒ exclusion (Iden3 notation).
//
// It delegates to the “leaf-hash” version after computing the
// Poseidon-based leaf commitments (`Hash1`).
func Verifier(
	api frontend.API,
	hFn utils.Hasher,
	enabled frontend.Variable, // 0 ⇒ proof disabled
	root frontend.Variable, // public input
	siblings []frontend.Variable, // packed top→bottom
	oldKey, oldValue, isOld0 frontend.Variable,
	key, value frontend.Variable,
	fnc frontend.Variable, // 0 = inc, 1 = exc
) frontend.Variable {

	hash1Old := Hash1(api, hFn, oldKey, oldValue) // H(oldKey‖oldValue‖1)
	hash1New := Hash1(api, hFn, key, value)       // H(key‖value‖1)

	return VerifierWithLeafHashFlag(
		api, hFn,
		enabled, root, siblings,
		oldKey, hash1Old, isOld0,
		key, hash1New, fnc,
	)
}

// VerifierWithLeafHash is a convenience wrapper around VerifierWithLeafHashFlag
// that asserts the result to be 1 (valid).
func VerifierWithLeafHash(
	api frontend.API,
	hFn utils.Hasher,
	enabled frontend.Variable,
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, hash1Old, isOld0 frontend.Variable,
	key, hash1New frontend.Variable,
	fnc frontend.Variable, // 0 =inclusion, 1 =exclusion
) {
	valid := VerifierWithLeafHashFlag(
		api, hFn,
		enabled, root, siblings,
		oldKey, hash1Old, isOld0,
		key, hash1New, fnc,
	)
	api.AssertIsEqual(valid, 1)
}

// VerifierWithLeafHashFlag rebuilds the root and returns 1 on success, 0 on failure.
func VerifierWithLeafHashFlag(
	api frontend.API,
	hFn utils.Hasher,
	enabled, // 1 → perform all checks, 0 → bypass (flag always 1)
	root frontend.Variable,
	siblings []frontend.Variable,
	oldKey, hash1Old, // leaf being deleted / updated
	isOld0, // 1 iff old leaf is the implicit-zero leaf
	key, hash1New, // leaf being inserted
	fnc frontend.Variable, // 0 inclusion, 1 exclusion
) frontend.Variable {

	nLevels := len(siblings)

	// -------------------------------------------------------------------------
	// 1. per-level state machines (same logic as before)
	// -------------------------------------------------------------------------
	n2bNew := api.ToBinary(key, api.Compiler().FieldBitLen())
	smtLevIns := LevIns(api, enabled, siblings)

	stTop, stI0, stIOld, stINew, stNa :=
		make([]frontend.Variable, nLevels),
		make([]frontend.Variable, nLevels),
		make([]frontend.Variable, nLevels),
		make([]frontend.Variable, nLevels),
		make([]frontend.Variable, nLevels)

	for i := 0; i < nLevels; i++ {
		if i == 0 {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] =
				VerifierSM(api, isOld0, smtLevIns[i], fnc,
					enabled, 0, 0, 0, api.Sub(1, enabled))
		} else {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] =
				VerifierSM(api, isOld0, smtLevIns[i], fnc,
					stTop[i-1], stI0[i-1], stIOld[i-1], stINew[i-1], stNa[i-1])
		}
	}

	// --- condition (1): exactly one state must be active on the last level ----
	sumStates := api.Add(api.Add(api.Add(stNa[nLevels-1],
		stIOld[nLevels-1]),
		stINew[nLevels-1]),
		stI0[nLevels-1])
	flagStates := IsEqual(api, sumStates, 1) // 1 iff ok

	// -------------------------------------------------------------------------
	// 2. hash-path rebuilding (bottom-up)
	// -------------------------------------------------------------------------
	levels := make([]frontend.Variable, nLevels)
	for i := nLevels - 1; i >= 0; i-- {
		next := frontend.Variable(0)
		if i != nLevels-1 {
			next = levels[i+1]
		}
		levels[i] = VerifierLevel(api, hFn,
			stTop[i], stIOld[i], stINew[i],
			siblings[i], hash1Old, hash1New,
			n2bNew[i], next)
	}

	// --- condition (2): “key reuse” must NOT happen for an update ------------
	areKeyEq := IsEqual(api, oldKey, key)
	keyReuseOK := MultiAnd(api, []frontend.Variable{
		fnc,                // exclusion ⇒ fnc==1 (no restriction)
		api.Sub(1, isOld0), // update path only when old exists
		areKeyEq,           // keys equal
		enabled,
	})
	flagKeyReuse := IsEqual(api, keyReuseOK, 0) // 1 iff ok

	// --- condition (3): computed root matches the supplied root --------------
	flagRoot := ForceEqualIfEnabledFlag(api,
		levels[0], root, enabled)

	// -------------------------------------------------------------------------
	// 3. global flag  (AND of all individual checks)
	// -------------------------------------------------------------------------
	return MultiAnd(api, []frontend.Variable{
		flagStates,
		flagKeyReuse,
		flagRoot,
	})
}
