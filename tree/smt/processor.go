package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// Processor computes the new SMT root from an old root, an update / insert
// operation and its Merkle-path witness.
//
//	fnc0 == 1  → update-existing-leaf   (keys must be equal)
//	fnc1 == 1  → insert-new-leaf        (keys may differ OR old leaf empty)
//
// Exactly one of fnc0, fnc1 must be 1.
func Processor(
	api frontend.API,
	hFn utils.Hasher,
	oldRoot frontend.Variable,
	siblings []frontend.Variable,
	oldKey, oldValue, isOld0 frontend.Variable,
	newKey, newValue frontend.Variable,
	fnc0, fnc1 frontend.Variable,
) (newRoot frontend.Variable) {

	hash1Old := Hash1(api, hFn, oldKey, oldValue)
	hash1New := Hash1(api, hFn, newKey, newValue)

	return ProcessorWithLeafHash(
		api, hFn,
		oldRoot, siblings,
		oldKey, hash1Old, isOld0,
		newKey, hash1New,
		fnc0, fnc1,
	)
}

// ProcessorWithLeafHash is identical to the Circom smtprocessor but
// uses Gnark hints to cut constraint overhead.
func ProcessorWithLeafHash(
	api frontend.API,
	hFn utils.Hasher,
	oldRoot frontend.Variable,
	siblings []frontend.Variable,
	oldKey, hash1Old, isOld0 frontend.Variable,
	newKey, hash1New frontend.Variable,
	fnc0, fnc1 frontend.Variable,
) (newRoot frontend.Variable) {

	levels := len(siblings)

	// 0.  Helper booleans and flags (identical to Circom)
	enabled := api.Sub(api.Add(fnc0, fnc1), api.Mul(fnc0, fnc1)) // XOR  (Circom line: enabled <== fnc[0]+fnc[1]-fnc[0]*fnc[1])
	api.AssertIsBoolean(enabled)

	// exactly one of the 4 op-codes must be 1 for (insert/update/delete/NOP).
	// Circom does *not* forbid delete (1,1); we mirror that.
	// fnc0 + fnc1 in {0,1,2}.  XOR already enforced by enabled, nothing else to do.

	// 1.  Key bit decomposition via hint   (saves 160*IsBoolean)
	n2bOld, err := api.Compiler().NewHint(KeyBitsDecompHint, levels, oldKey)
	if err != nil {
		panic(err)
	}
	n2bNew, err := api.Compiler().NewHint(KeyBitsDecompHint, levels, newKey)
	if err != nil {
		panic(err)
	}

	// bits → boolean  &  Σ 2^i·bit = key
	scale := frontend.Variable(1)
	sumOld, sumNew := frontend.Variable(0), frontend.Variable(0)

	for i := range levels {
		api.AssertIsBoolean(n2bOld[i])
		api.AssertIsBoolean(n2bNew[i])

		sumOld = api.Add(sumOld, api.Mul(n2bOld[i], scale))
		sumNew = api.Add(sumNew, api.Mul(n2bNew[i], scale))
		scale = api.Add(scale, scale) // ×2
	}
	api.AssertIsEqual(sumOld, oldKey)
	api.AssertIsEqual(sumNew, newKey)

	// 2.  First-different-bit hint – only for extra sanity (optional)
	fdOut, err := api.Compiler().NewHint(FirstDiffHint, 2, oldKey, newKey)
	if err != nil {
		panic(err)
	}
	diffIdx, eqFlag := fdOut[0], fdOut[1]
	api.AssertIsBoolean(eqFlag)
	ForceEqualIfEnabled(api, diffIdx, levels, eqFlag)
	ForceEqualIfEnabled(api, oldKey, newKey, eqFlag)

	// 3.  LevIns  (always enabled ↔ Circom behaviour)
	smtLevIns := LevIns(api, enabled /* same as Circom */, siblings)

	// 4.  XOR bits for state machine
	xorBits := make([]frontend.Variable, levels)
	for i := range levels {
		xorBits[i] = api.Xor(n2bOld[i], n2bNew[i])
	}

	// 5.  Run the Processor state machine level-by-level
	stTop, stOld0 := make([]frontend.Variable, levels), make([]frontend.Variable, levels)
	stBot, stNew1 := make([]frontend.Variable, levels), make([]frontend.Variable, levels)
	stNa, stUpd := make([]frontend.Variable, levels), make([]frontend.Variable, levels)

	for i := range levels {
		if i == 0 {
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] =
				ProcessorSM(api,
					xorBits[i], isOld0, smtLevIns[i], fnc0,
					enabled, // prev_top
					0, 0, 0, // prev_old0/bot/new1
					api.Sub(1, enabled), // prev_na
					0)                   // prev_upd
		} else {
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] =
				ProcessorSM(api,
					xorBits[i], isOld0, smtLevIns[i], fnc0,
					stTop[i-1], stOld0[i-1], stBot[i-1],
					stNew1[i-1], stNa[i-1], stUpd[i-1])
		}
	}

	// unique final state  (Circom: st_na + st_new1 + st_old0 + st_upd === 1)
	api.AssertIsEqual(
		api.Add(api.Add(stNa[levels-1], stNew1[levels-1]),
			api.Add(stOld0[levels-1], stUpd[levels-1])),
		1)

	// 6.  Bottom-up hash recomputation (ProcessorLevel)
	oldLvl, newLvl := make([]frontend.Variable, levels), make([]frontend.Variable, levels)

	for i := levels - 1; i >= 0; i-- {
		if i == levels-1 {
			oldLvl[i], newLvl[i] =
				ProcessorLevel(api, hFn,
					stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i],
					siblings[i], hash1Old, hash1New, n2bNew[i],
					0, 0)
		} else {
			oldLvl[i], newLvl[i] =
				ProcessorLevel(api, hFn,
					stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i],
					siblings[i], hash1Old, hash1New, n2bNew[i],
					oldLvl[i+1], newLvl[i+1])
		}
	}

	// 7.  Root equality & selector (exact Circom formula)
	left, right := Switcher(api, api.Mul(fnc0, fnc1), oldLvl[0], newLvl[0])

	// if enabled → oldRoot must match L
	ForceEqualIfEnabled(api, oldRoot, left, enabled)

	// newRoot = oldRoot   when !enabled
	// newRoot = R         when  enabled
	newRoot = api.Add(api.Mul(enabled, api.Sub(right, oldRoot)), oldRoot)

	// 8.  “keysOk” guard  (unchanged)
	eqKeys := IsEqual(api, oldKey, newKey)
	keysOk := MultiAnd(api, []frontend.Variable{
		api.Sub(1, fnc0), // 1-fnc0
		fnc1,             // fnc1
		api.Sub(1, eqKeys),
	},
	)
	api.AssertIsEqual(keysOk, 0)

	return
}
