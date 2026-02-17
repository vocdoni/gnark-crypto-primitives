package native

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/hash"
	"github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/mimc7"
	"github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon"
)

// MiMC7 returns a new instance of the MiMC7 hash function to be used in
// circuits which curve is the same of the MiMC7 itself (BN254).
func MiMC7(api frontend.API) (hash.Hash[frontend.Variable], error) {
	return mimc7.New(api)
}

// Poseidon returns a new instance of the Poseidon hash function to be used in
// circuits which curve is the same of the Poseidon itself (BN254).
func Poseidon(api frontend.API) (hash.Hash[frontend.Variable], error) {
	return poseidon.New(api)
}
