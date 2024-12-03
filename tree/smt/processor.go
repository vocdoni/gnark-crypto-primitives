package smt

import (
	"github.com/consensys/gnark/frontend"
)

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessor.circom

func Processor(api frontend.API, oldRoot frontend.Variable, siblings []frontend.Variable, oldKey, oldValue, isOld0, newKey, newValue, fnc0, fnc1 frontend.Variable) (newRoot frontend.Variable) {
	levels := len(siblings)
	enabled := api.Sub(api.Add(fnc0, fnc1), api.Mul(fnc0, fnc1))
	hash1Old := Hash1(api, oldKey, oldValue)
	hash1New := Hash1(api, newKey, newValue)
	n2bOld := api.ToBinary(oldKey, api.Compiler().FieldBitLen())
	n2bNew := api.ToBinary(newKey, api.Compiler().FieldBitLen())
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

	api.AssertIsEqual(api.Add(api.Add(stNa[levels-1], stNew1[levels-1]), api.Add(stOld0[levels-1], stUpd[levels-1])), 1)

	levelsOldRoot := make([]frontend.Variable, levels)
	levelsNewRoot := make([]frontend.Variable, levels)
	for i := levels - 1; i >= 0; i-- {
		if i == levels-1 {
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], 0, 0)
		} else {
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], levelsOldRoot[i+1], levelsNewRoot[i+1])
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
	return
}
