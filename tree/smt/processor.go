package smt

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessor.circom

func Processor(api frontend.API, hFn utils.Hasher, oldRoot frontend.Variable, siblings []frontend.Variable, oldKey, oldValue, isOld0, newKey, newValue, fnc0, fnc1 frontend.Variable) (newRoot frontend.Variable) {
	hash1Old := Hash1(api, hFn, oldKey, oldValue)
	hash1New := Hash1(api, hFn, newKey, newValue)
	return ProcessorWithLeafHash(api, hFn, oldRoot, siblings, oldKey, hash1Old, isOld0, newKey, hash1New, fnc0, fnc1)
}

func ProcessorWithLeafHash(api frontend.API, hFn utils.Hasher, oldRoot frontend.Variable, siblings []frontend.Variable, oldKey, hash1Old, isOld0, newKey, hash1New, fnc0, fnc1 frontend.Variable) (newRoot frontend.Variable) {
	levels := len(siblings)
	enabled := api.Sub(api.Add(fnc0, fnc1), api.Mul(fnc0, fnc1))

	n2bOld := getLowBits(api, oldKey, levels) // Optimized decomposition
	n2bNew := getLowBits(api, newKey, levels) // Optimized decomposition

	smtLevIns := LevIns(api, enabled, siblings)

	xors := make([]frontend.Variable, levels)
	for i := 0; i < levels; i++ {
		xors[i] = api.Xor(n2bOld[i], n2bNew[i])
	}

	stTop := make([]frontend.Variable, levels)
	stOld0 := make([]frontend.Variable, levels)
	stBot := make([]frontend.Variable, levels)
	stNew1 := make([]frontend.Variable, levels)
	stNa := make([]frontend.Variable, levels)
	stUpd := make([]frontend.Variable, levels)
	for i := 0; i < levels; i++ {
		if i == 0 {
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] = ProcessorSM(api, xors[i], isOld0, smtLevIns[i], fnc0, enabled, 0, 0, 0, api.Sub(1, enabled), 0)
		} else {
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] = ProcessorSM(api, xors[i], isOld0, smtLevIns[i], fnc0, stTop[i-1], stOld0[i-1], stBot[i-1], stNew1[i-1], stNa[i-1], stUpd[i-1])
		}
	}

	api.AssertIsEqual(api.Add(stNa[levels-1], stNew1[levels-1], stOld0[levels-1], stUpd[levels-1]), 1) // Optimized Add

	levelsOldRoot := make([]frontend.Variable, levels)
	levelsNewRoot := make([]frontend.Variable, levels)
	for i := levels - 1; i >= 0; i-- {
		if i == levels-1 {
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, hFn, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], 0, 0)
		} else {
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, hFn, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], levelsOldRoot[i+1], levelsNewRoot[i+1])
		}
	}

	topSwitcherL, topSwitcherR := Switcher(api, api.Mul(fnc0, fnc1), levelsOldRoot[0], levelsNewRoot[0])
	ForceEqualIfEnabled(api, oldRoot, topSwitcherL, enabled)

	newRoot = api.Add(api.Mul(enabled, api.Sub(topSwitcherR, oldRoot)), oldRoot)

	areKeyEquals := IsEqual(api, oldKey, newKey)
	in := []frontend.Variable{
		api.Sub(1, fnc0),
		fnc1,
		api.Sub(1, areKeyEquals),
	}
	keysOk := MultiAnd(api, in)
	api.AssertIsEqual(keysOk, 0)
	return newRoot
}

// getLowBits returns the lower nBits of val as a slice of bits.
// It uses a hint to calculate the higher part of the value.
// This is more efficient than a full api.ToBinary if nBits is small.
func getLowBits(api frontend.API, val frontend.Variable, nBits int) []frontend.Variable {
	// get the high part of the value
	high, err := api.NewHint(RightShiftHint, 1, val, nBits)
	if err != nil {
		// should not happen
		panic(err)
	}

	// low = val - high * 2^nBits
	base := big.NewInt(1)
	base.Lsh(base, uint(nBits))

	low := api.Sub(val, api.Mul(high, base))

	// constrain low to be nBits and return the bits
	return api.ToBinary(low, nBits)
}
