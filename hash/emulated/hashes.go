package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/vocdoni/gnark-crypto-primitives/hash"
	"github.com/vocdoni/gnark-crypto-primitives/hash/emulated/bn254/mimc7"
	"github.com/vocdoni/gnark-crypto-primitives/hash/emulated/bn254/poseidon"
)

// MiMC7 returns a new instance of the MiMC7 hash function to be used in
// circuits wich curve is the same of the MiMC7 itself (BN254).
func MiMC7(api frontend.API) (hash.Hash[emulated.Element[sw_bn254.ScalarField]], error) {
	return mimc7.New(api)
}

// Poseidon returns a new instance of the Poseidon hash function to be used in
// circuits wich curve is the same of the Poseidon itself (BN254).
func Poseidon(api frontend.API) (hash.Hash[emulated.Element[sw_bn254.ScalarField]], error) {
	return poseidon.New(api)
}
