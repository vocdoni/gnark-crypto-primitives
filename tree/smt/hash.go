package smt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smthash_poseidon.circom

func Hash1(api frontend.API, hFn utils.Hasher, key frontend.Variable, values ...frontend.Variable) frontend.Variable {
	inputs := []frontend.Variable{key}
	inputs = append(inputs, values...)
	inputs = append(inputs, 1)
	hash, err := hFn(api, inputs...)
	if err != nil {
		panic(err)
	}
	return hash
}

func Hash2(api frontend.API, hFn utils.Hasher, l, r frontend.Variable) frontend.Variable {
	hash, err := hFn(api, l, r)
	if err != nil {
		panic(err)
	}
	return hash
}
