package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mdehoog/gnark-circom-smt/circuits/smt"
)

func InclusionVerifier[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], root *emulated.Element[T], siblings []*emulated.Element[T], key, value *emulated.Element[T]) {
	Verifier[T](api, field, 1, root, siblings, key, value, 0, key, value, 0)
}

func ExclusionVerifier[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], root *emulated.Element[T], siblings []*emulated.Element[T], oldKey, oldValue *emulated.Element[T], isOld0 frontend.Variable, key *emulated.Element[T]) {
	zero := emulated.ValueOf[T](0)
	Verifier[T](api, field, 1, root, siblings, oldKey, oldValue, isOld0, key, &zero, 1)
}

func Verifier[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], enabled frontend.Variable, root *emulated.Element[T], siblings []*emulated.Element[T], oldKey, oldValue *emulated.Element[T], isOld0 frontend.Variable, key, value *emulated.Element[T], fnc frontend.Variable) {
	nLevels := len(siblings)
	hash1Old := Hash1(field, oldKey, oldValue)
	hash1New := Hash1(field, key, value)
	n2bNew := field.ToBits(key)
	smtLevIns := LevIns(api, field, enabled, siblings)

	stTop := make([]frontend.Variable, nLevels)
	stI0 := make([]frontend.Variable, nLevels)
	stIOld := make([]frontend.Variable, nLevels)
	stINew := make([]frontend.Variable, nLevels)
	stNa := make([]frontend.Variable, nLevels)
	for i := 0; i < nLevels; i++ {
		if i == 0 {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = smt.VerifierSM(api, isOld0, smtLevIns[i], fnc, enabled, 0, 0, 0, api.Sub(1, enabled))
		} else {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = smt.VerifierSM(api, isOld0, smtLevIns[i], fnc, stTop[i-1], stI0[i-1], stIOld[i-1], stINew[i-1], stNa[i-1])
		}
	}
	api.AssertIsEqual(api.Add(api.Add(api.Add(stNa[nLevels-1], stIOld[nLevels-1]), stINew[nLevels-1]), stI0[nLevels-1]), 1)

	levels := make([]*emulated.Element[T], nLevels)
	for i := nLevels - 1; i >= 0; i-- {
		if i == nLevels-1 {
			zero := emulated.ValueOf[T](0)
			levels[i] = VerifierLevel(api, field, stTop[i], stIOld[i], stINew[i], siblings[i], hash1Old, hash1New, n2bNew[i], &zero)
		} else {
			levels[i] = VerifierLevel(api, field, stTop[i], stIOld[i], stINew[i], siblings[i], hash1Old, hash1New, n2bNew[i], levels[i+1])
		}
	}

	areKeyEquals := IsEqual(field, oldKey, key)
	keysOk := smt.MultiAnd(api, []frontend.Variable{fnc, api.Sub(1, isOld0), areKeyEquals, enabled})
	api.AssertIsEqual(keysOk, 0)
	ForceEqualIfEnabled(field, levels[0], root, enabled)
}
