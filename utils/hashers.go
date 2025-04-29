package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
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

// ----------------------------------------------------------------------------
//  Poseidon-2 Merkle–Damgård hasher (width-2)
//  compatible with Arbo's HashPoseidon2 on the Go side
// ----------------------------------------------------------------------------

// Poseidon2Hasher hashes 2- or 3-element tuples:
//   - 2 elements ⇒ internal node  ->  min‖max
//   - 3 elements ⇒ leaf           ->  key‖value‖flag
func Poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	// ---- order the two-input case (min‖max)
	if len(data) == 2 {
		// isGreater = 1  ⇔  data[0] > data[1]
		isGreater := api.Sub(1, cmp.IsLessOrEqual(api, data[0], data[1]))
		left := api.Select(isGreater, data[1], data[0])  // min
		right := api.Select(isGreater, data[0], data[1]) // max
		data = []frontend.Variable{left, right}
	}

	// ---- width-2 Poseidon2 permutation
	perm, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return 0, err
	}

	// ---- Merkle–Damgård chaining
	cv := frontend.Variable(0) // CV₀ = 0
	for _, m := range data {
		state := []frontend.Variable{cv, m} // [CVᵢ , mᵢ]
		if err := perm.Permutation(state); err != nil {
			return 0, err
		}
		cv = api.Add(state[1], m) // CVᵢ₊₁ = S₁ + mᵢ
	}
	return cv, nil
}
