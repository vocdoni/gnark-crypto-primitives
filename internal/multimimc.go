package internal

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/mimc7"
)

const maxInputs = 62

func MultiMiMC7(arr []*big.Int, key *big.Int) (*big.Int, error) {
	if len(arr) < maxInputs {
		return mimc7.Hash(arr, key)
	} else if len(arr)/maxInputs > maxInputs {
		return nil, fmt.Errorf("too many inputs, max is %d", maxInputs*maxInputs)
	}
	// calculate chunk hashes
	hashed := []*big.Int{}
	chunk := []*big.Int{}
	for _, v := range arr {
		if len(chunk) == maxInputs {
			hash, err := mimc7.Hash(chunk, key)
			if err != nil {
				return nil, err
			}
			hashed = append(hashed, hash)
			chunk = []*big.Int{}
		}
		chunk = append(chunk, v)
	}
	// if the final chunk is not empty, hash it to get the last chunk hash
	if len(chunk) > 0 {
		hash, err := mimc7.Hash(chunk, key)
		if err != nil {
			return nil, err
		}
		hashed = append(hashed, hash)
	}
	// if there is only one chunk, return its hash
	if len(hashed) == 1 {
		return hashed[0], nil
	}
	return mimc7.Hash(hashed, key)
}
