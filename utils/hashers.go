package utils

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

type Hasher func(frontend.API, ...frontend.Variable) (frontend.Variable, error)

// MiMCHasher is a hash function that hashes the data provided using the
// mimc hash function and the current compiler field. It is used to hash the
// leaves of the census tree during the proof verification.
func MiMCHasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return 0, err
	}
	h.Write(data...)
	return h.Sum(), nil
}

// Poseidon2Hasher hashes either an internal-node (2 inputs, tag 0)
// or a leaf      (3 inputs, tag 1) and returns lane 0.
//
// It is bit-for-bit compatible with the Go implementation that calls
//
//	SpongeAbsorb( t=3, rF=8, rP=56 ).
func Poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	if len(data) != 2 && len(data) != 3 {
		return 0, fmt.Errorf("Poseidon2: expected 2 or 3 inputs, got %d", len(data))
	}

	// ─────── canonical ordering for the 2-input case ───────
	if len(data) == 2 {
		// cmp = 1  if data[0] > data[1]
		cmp := api.Cmp(data[0], data[1])     // −1 , 0 , +1
		isGT := api.IsZero(api.Add(cmp, -1)) // 1 iff cmp == +1
		// swap when data[0] > data[1]
		left := api.Select(isGT, data[1], data[0])  // min
		right := api.Select(isGT, data[0], data[1]) // max
		data = []frontend.Variable{left, right}
	}

	tag := 0
	if len(data) == 3 {
		tag = 1
	}

	perm, err := poseidon2.NewPoseidon2FromParameters(api, 3, 8, 56)
	if err != nil {
		return 0, err
	}

	state := []frontend.Variable{data[0], data[1], tag}
	if err := perm.Permutation(state); err != nil {
		return 0, err
	}
	if len(data) == 2 {
		return state[0], nil
	}

	state[0] = data[2] // absorb flag
	if err := perm.Permutation(state); err != nil {
		return 0, err
	}
	return state[0], nil
}
