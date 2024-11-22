package address

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// elemToU8 converts a field element to a slice of uint8 by converting each
// limb to a slice of uint8 and concatenating them.
func elemToU8[T emulated.FieldParams](api frontend.API, elem emulated.Element[T]) ([]uints.U8, error) {
	bf, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	// convert each limb to []uint8
	var res []uints.U8
	for _, limb := range elem.Limbs {
		bLimb := bf.ValueOf(limb)
		for _, b := range bLimb {
			res = append(res, b)
		}
	}
	return res, nil
}

// u8ToVar converts a slice of uint8 to a variable by multiplying the current
// result by 256 and adding the next byte, starting from the most significant
// byte.
func u8ToVar(api frontend.API, u8 []uints.U8) (frontend.Variable, error) {
	res := frontend.Variable(0)
	b := frontend.Variable(256)
	// convert each byte to a variable and sum them
	for i := 0; i < len(u8); i++ {
		res = api.Mul(res, b)
		res = api.Add(res, u8[i].Val)
	}
	return res, nil
}

// swapEndianness swaps the endianness of a slice of uint8 by reversing it.
func swapEndianness(u8 []uints.U8) []uints.U8 {
	var swap []uints.U8
	for i := len(u8) - 1; i >= 0; i-- {
		swap = append(swap, u8[i])
	}
	return swap
}

// DeriveAddress derives an Ethereum address from a public key by hashing the
// public key and returning the last 20 bytes of the hash as an address into a
// variable. It also returns the address with the bytes in little-endian order.
func DeriveAddress(api frontend.API, pubKey ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]) (frontend.Variable, frontend.Variable, error) {
	// convert public key coords to uint8 and concatenate them
	xBytes, err := elemToU8(api, pubKey.X)
	if err != nil {
		return 0, 0, err
	}
	yBytes, err := elemToU8(api, pubKey.Y)
	if err != nil {
		return 0, 0, err
	}
	// swap endianness of the bytes and concatenate them
	pubBytes := append(swapEndianness(xBytes), swapEndianness(yBytes)...)
	// hash the public key
	keccak, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return 0, 0, err
	}
	keccak.Write(pubBytes)
	hash := keccak.Sum()
	// return the last 20 bytes of the hash as an address
	addrBytes := hash[12:]
	addr, err := u8ToVar(api, addrBytes)
	if err != nil {
		return 0, 0, err
	}
	addrLE, err := u8ToVar(api, swapEndianness(addrBytes))
	if err != nil {
		return 0, 0, err
	}
	return addr, addrLE, nil
}
