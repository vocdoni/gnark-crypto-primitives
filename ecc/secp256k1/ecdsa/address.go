package ecdsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

// DeriveAddress derives an Ethereum address from a public key over Secp256k1
// by hashing the public key with Keccak256 and returning the last 20 bytes of
// the hash as an address into a variable.
func DeriveAddress(api frontend.API, pubKey ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]) (frontend.Variable, error) {
	// convert public key coords to uint8 and concatenate them
	xBytes, err := utils.ElemToU8(api, pubKey.X)
	if err != nil {
		return 0, err
	}
	yBytes, err := utils.ElemToU8(api, pubKey.Y)
	if err != nil {
		return 0, err
	}
	// swap endianness of the bytes and concatenate them
	pubBytes := append(utils.SwapEndianness(xBytes), utils.SwapEndianness(yBytes)...)
	// hash the public key
	keccak, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return 0, err
	}
	keccak.Write(pubBytes)
	hash := keccak.Sum()
	// return the last 20 bytes of the hash as an address
	addrBytes := hash[12:]
	addr, err := utils.U8ToVar(api, addrBytes)
	if err != nil {
		return 0, err
	}
	return addr, nil
}
