package poseidon2

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

// MinMaxHint: given (a,b) returns (min(a,b), max(a,b))
var MinMaxHint solver.Hint = func(_ *big.Int, in, out []*big.Int) error {
	if in[0].Cmp(in[1]) <= 0 {
		out[0].Set(in[0]) // min
		out[1].Set(in[1]) // max
	} else {
		out[0].Set(in[1])
		out[1].Set(in[0])
	}
	return nil
}
