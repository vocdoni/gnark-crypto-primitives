package arbo

import "math/big"

func ValidSiblings(_ *big.Int, inputs, results []*big.Int) error {
	limit := inputs[0]
	siblings := inputs[1:]
	for i := range siblings {
		if limit.Cmp(new(big.Int).SetUint64(uint64(i))) == 1 {
			results[i] = new(big.Int).SetUint64(1)
		}
	}
	return nil
}
