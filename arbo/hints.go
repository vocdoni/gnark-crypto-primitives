package arbo

import (
	"fmt"
	"math/big"
)

// ValidSiblings hint function creates a binary map with the slots where a
// valid sibling is located in the siblings list. This function helps to skip
// unnecessary iterations when walking through the merkle tree. The first input
// is the number of valid siblings. The resulting slice length must be greater
// than or equal to nsiblings.
func ValidSiblings(_ *big.Int, inputs, results []*big.Int) error {
	nsiblings := inputs[0]
	if nsiblings.Cmp(new(big.Int).SetInt64(int64(len(results)))) == 1 {
		return fmt.Errorf("nsiblings must be less or equal to len(results)")
	}

	for i := uint64(0); i < nsiblings.Uint64(); i++ {
		if nsiblings.Cmp(new(big.Int).SetUint64(uint64(i))) == 1 {
			results[i] = new(big.Int).SetUint64(1)
		}
	}
	return nil
}
