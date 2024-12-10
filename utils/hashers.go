package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
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
