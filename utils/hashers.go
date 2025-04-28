package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
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

// Poseidon2Hasher is a hash function that hashes the data provided using the
// poseidon2 hash function and the current compiler field.
func poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	params := poseidon2bn254.GetDefaultParameters()
	f, err := poseidon2.NewPoseidon2FromParameters(
		api,
		params.Width,
		params.NbFullRounds,
		params.NbPartialRounds,
	)
	if err != nil {
		return 0, err
	}
	h := hash.NewMerkleDamgardHasher(api, f, make([]byte, fr.Bytes))
	h.Write(data...)
	return h.Sum(), nil
}

// NormalizedPoseidon2Hasher is a wrapper around Poseidon2Hasher that ensures
// inputs are deterministically ordered. This eliminates hash output differences
// caused by input ordering variations between different path calculation methods.
//
// When used with exactly 2 inputs, it sorts them deterministically:
// - Input ordering doesn't affect the hash output: hash(a,b) == hash(b,a)
// - For other input counts, it passes through to standard Poseidon2Hasher
//
// This is especially useful for Merkle tree operations where path bit calculation
// differences between implementations could lead to different hash orderings.
func Poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	// For Merkle intermediate nodes, we expect exactly 2 inputs
	// (left child and right child)
	if len(data) == 2 {
		// Normalize the order of inputs by comparing them and sorting
		// api.Cmp returns -1, 0, or 1, but api.Select expects 0 or 1
		// We need to convert the three-way comparison to a binary condition
		cmpResult := api.Cmp(data[0], data[1])

		// Create a binary condition: 1 when data[0] < data[1], 0 otherwise
		// When data[0] < data[1], cmpResult is -1, so api.Add(cmpResult, 1) is 0
		// and api.IsZero returns 1
		isLessThan := api.IsZero(api.Add(cmpResult, 1))

		// Select the smaller value as the first input, larger as the second
		// This ensures hash(a,b) == hash(b,a)
		first := api.Select(isLessThan, data[0], data[1])
		second := api.Select(isLessThan, data[1], data[0])

		// Call the standard Poseidon2 with normalized inputs
		return poseidon2Hasher(api, first, second)
	}

	// For other cases (single input or more than 2 inputs),
	// pass through to the standard Poseidon2 hasher
	return poseidon2Hasher(api, data...)
}
