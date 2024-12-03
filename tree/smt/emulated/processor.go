package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mdehoog/gnark-circom-smt/circuits/smt"
)

// based on https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/smt/smtprocessor.circom

func Processor[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], oldRoot *emulated.Element[T], siblings []*emulated.Element[T], oldKey, oldValue *emulated.Element[T], isOld0 frontend.Variable, newKey, newValue *emulated.Element[T], fnc0, fnc1 frontend.Variable) (newRoot *emulated.Element[T]) {
	levels := len(siblings)
	enabled := api.Sub(api.Add(fnc0, fnc1), api.Mul(fnc0, fnc1))
	hash1Old := Hash1(field, oldKey, oldValue)
	hash1New := Hash1(field, newKey, newValue)
	n2bOld := field.ToBits(oldKey)
	n2bNew := field.ToBits(newKey)
	smtLevIns := LevIns(api, field, enabled, siblings)

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
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] = smt.ProcessorSM(api, xors[i], isOld0, smtLevIns[i], fnc0, enabled, 0, 0, 0, api.Sub(1, enabled), 0)
		} else {
			stTop[i], stOld0[i], stBot[i], stNew1[i], stNa[i], stUpd[i] = smt.ProcessorSM(api, xors[i], isOld0, smtLevIns[i], fnc0, stTop[i-1], stOld0[i-1], stBot[i-1], stNew1[i-1], stNa[i-1], stUpd[i-1])
		}
	}

	api.AssertIsEqual(api.Add(api.Add(stNa[levels-1], stNew1[levels-1]), api.Add(stOld0[levels-1], stUpd[levels-1])), 1)

	levelsOldRoot := make([]*emulated.Element[T], levels)
	levelsNewRoot := make([]*emulated.Element[T], levels)
	for i := levels - 1; i >= 0; i-- {
		if i == levels-1 {
			zero := emulated.ValueOf[T](0)
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, field, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], &zero, &zero)
		} else {
			levelsOldRoot[i], levelsNewRoot[i] = ProcessorLevel(api, field, stTop[i], stOld0[i], stBot[i], stNew1[i], stUpd[i], siblings[i], hash1Old, hash1New, n2bNew[i], levelsOldRoot[i+1], levelsNewRoot[i+1])
		}
	}

	topSwitcherL, topSwitcherR := Switcher(field, api.Mul(fnc0, fnc1), levelsOldRoot[0], levelsNewRoot[0])
	ForceEqualIfEnabled(field, oldRoot, topSwitcherL, enabled)

	newRoot = field.Select(enabled, topSwitcherR, oldRoot)

	areKeyEquals := IsEqual(field, oldKey, newKey)
	in := []frontend.Variable{
		api.Sub(1, fnc0),
		fnc1,
		api.Sub(1, areKeyEquals),
	}
	keysOk := smt.MultiAnd(api, in)
	api.AssertIsEqual(keysOk, 0)
	return
}
