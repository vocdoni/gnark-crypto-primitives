package smt

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(RightShiftHint)
}

// RightShiftHint computes x >> shift.
// inputs[0] = x
// inputs[1] = shift
func RightShiftHint(_ *big.Int, inputs, outputs []*big.Int) error {
	shift := inputs[1].Uint64()
	outputs[0].Rsh(inputs[0], uint(shift))
	return nil
}
