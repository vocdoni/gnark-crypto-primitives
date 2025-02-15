package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

func InclusionVerifier(api frontend.API, hFn utils.Hasher, root frontend.Variable, siblings []frontend.Variable, key, value frontend.Variable) {
	Verifier(api, hFn, 1, root, siblings, key, value, 0, key, value, 0)
}

func ExclusionVerifier(api frontend.API, hFn utils.Hasher, root frontend.Variable, siblings []frontend.Variable, oldKey, oldValue, isOld0, key frontend.Variable) {
	Verifier(api, hFn, 1, root, siblings, oldKey, oldValue, isOld0, key, 0, 1)
}

func Verifier(api frontend.API, hFn utils.Hasher, enabled, root frontend.Variable, siblings []frontend.Variable, oldKey, oldValue, isOld0, key, value, fnc frontend.Variable) {
	hash1Old := Hash1(api, hFn, oldKey, oldValue)
	hash1New := Hash1(api, hFn, key, value)
	VerifierWithLeafHash(api, hFn, enabled, root, siblings, oldKey, hash1Old, isOld0, key, hash1New, fnc)
}

func VerifierWithLeafHash(api frontend.API, hFn utils.Hasher, enabled, root frontend.Variable, siblings []frontend.Variable, oldKey, hash1Old, isOld0, key, hash1New, fnc frontend.Variable) {
	nLevels := len(siblings)
	n2bNew := api.ToBinary(key, api.Compiler().FieldBitLen())
	smtLevIns := LevIns(api, enabled, siblings)

	stTop := make([]frontend.Variable, nLevels)
	stI0 := make([]frontend.Variable, nLevels)
	stIOld := make([]frontend.Variable, nLevels)
	stINew := make([]frontend.Variable, nLevels)
	stNa := make([]frontend.Variable, nLevels)
	for i := 0; i < nLevels; i++ {
		if i == 0 {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = VerifierSM(api, isOld0, smtLevIns[i], fnc, enabled, 0, 0, 0, api.Sub(1, enabled))
		} else {
			stTop[i], stI0[i], stIOld[i], stINew[i], stNa[i] = VerifierSM(api, isOld0, smtLevIns[i], fnc, stTop[i-1], stI0[i-1], stIOld[i-1], stINew[i-1], stNa[i-1])
		}
	}
	api.AssertIsEqual(api.Add(api.Add(api.Add(stNa[nLevels-1], stIOld[nLevels-1]), stINew[nLevels-1]), stI0[nLevels-1]), 1)

	levels := make([]frontend.Variable, nLevels)
	for i := nLevels - 1; i >= 0; i-- {
		if i == nLevels-1 {
			levels[i] = VerifierLevel(api, hFn, stTop[i], stIOld[i], stINew[i], siblings[i], hash1Old, hash1New, n2bNew[i], 0)
		} else {
			levels[i] = VerifierLevel(api, hFn, stTop[i], stIOld[i], stINew[i], siblings[i], hash1Old, hash1New, n2bNew[i], levels[i+1])
		}
	}

	areKeyEquals := IsEqual(api, oldKey, key)
	keysOk := MultiAnd(api, []frontend.Variable{fnc, api.Sub(1, isOld0), areKeyEquals, enabled})
	api.AssertIsEqual(keysOk, 0)
	ForceEqualIfEnabled(api, levels[0], root, enabled)
}
