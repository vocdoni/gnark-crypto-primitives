package smt

import (
	"github.com/consensys/gnark/frontend"

	"github.com/mdehoog/poseidon/circuits/poseidon"
)

// based on https://github.com/iden3/circomlib/blob/master/circuits/smt/smthash_poseidon.circom

func Hash1(api frontend.API, key, value frontend.Variable) frontend.Variable {
	inputs := []frontend.Variable{key, value, 1}
	return poseidon.Hash(api, inputs)
}

func Hash2(api frontend.API, l, r frontend.Variable) frontend.Variable {
	inputs := []frontend.Variable{l, r}
	return poseidon.Hash(api, inputs)
}
