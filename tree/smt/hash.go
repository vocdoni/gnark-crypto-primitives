package smt

import (
	"github.com/consensys/gnark/frontend"

	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
)

// based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smthash_poseidon.circom

func Hash1(api frontend.API, key, value frontend.Variable) frontend.Variable {
	inputs := []frontend.Variable{key, value, 1}
	hash, err := poseidon.MultiHash(api, inputs...)
	if err != nil {
		panic(err)
	}
	return hash
}

func Hash2(api frontend.API, l, r frontend.Variable) frontend.Variable {
	inputs := []frontend.Variable{l, r}
	hash, err := poseidon.MultiHash(api, inputs...)
	if err != nil {
		panic(err)
	}
	return hash
}
