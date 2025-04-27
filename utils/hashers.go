package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"

	//"github.com/consensys/gnark/std/hash/poseidon2"
	poseidon2bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
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
func Poseidon2Hasher(api frontend.API, data ...frontend.Variable) (frontend.Variable, error) {
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
	h := hash.NewMerkleDamgardHasher(api, f, 0)
	h.Write(data...)
	return h.Sum(), nil
}
