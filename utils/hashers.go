package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon2"
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

// PoseidonHasher wraps the Poseidon hash function from the gnark library.
func PoseidonHasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	return poseidon.Hash(api, data...)
}

// Poseidon-2 Merkle–Damgård hasher (width-2) compatible with Circom SMT
//
// Poseidon2Hasher hashes 2- or 3-element tuples:
//   - 2 elements ⇒ internal node  ->  min‖max
//   - 3 elements ⇒ leaf           ->  key‖value‖flag
func Poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
	return poseidon2.HashPoseidon2Gnark(api, data...)
}
