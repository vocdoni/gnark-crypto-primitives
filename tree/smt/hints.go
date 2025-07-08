package smt

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

/*
Safety of hints notes:

KeyBitsDecompHint — every bit is forced boolean and the weighted
sum is forced equal to the key, so the prover can’t fake any bit.

FirstDiffHint — its equality flag is validated with

ForceEqualIfEnabled; the sentinel check ensures the index is correct
when the keys are equal.

Even if the prover lied about diffIdx when eqFlag = 0, it never
influences any path logic, so no constraint is weakened.
*/

var Levels int

// Register hint functions and initialize levels
func init() {
	Levels = 160 // default
	solver.RegisterHint(
		KeyBitsDecompHint,
		FirstDiffHint,
		SiblingZerosHint,
		MultiInvZeroHint,
	)
}

// KeyBitsDecompHint decomposes a field element (key) into bits.
// It outputs len(outputs) bits (0/1 values) representing the key, least-significant bit first.
func KeyBitsDecompHint(q *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("KeyBitsDecompHint expects 1 input (the key)")
	}
	key := new(big.Int).Set(inputs[0])
	// Ensure key is in [0, q) by mod (inputs are already mod field in gnark, but to be safe)
	key.Mod(key, q)
	// Fill output bits
	for i := range outputs {
		// outputs[i] = i-th bit of key (LSB is bit 0)
		bit := key.Bit(i) // 0 or 1
		outputs[i] = new(big.Int).SetUint64(uint64(bit))
	}
	return nil
}

// FirstDiffHint returns
//
//	outputs[0] = index of the most-significant differing bit (0 = LSB, levels-1 = MSB)
//	             or sentinel = levels if keys are identical
//	outputs[1] = 1 iff keys are equal; 0 otherwise
//
// NB: The sentinel equals the tree depth requested by the circuit (global var `levels`).
func FirstDiffHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return fmt.Errorf("FirstDiffHint expects 2 inputs and 2 outputs")
	}
	depth := Levels // ← **always coherent with circuit**
	if depth <= 0 {
		return fmt.Errorf("invalid tree depth (%d)", depth)
	}

	oldKey := new(big.Int).Mod(inputs[0], q)
	newKey := new(big.Int).Mod(inputs[1], q)

	// Case: keys equal
	if oldKey.Cmp(newKey) == 0 {
		if outputs[0] == nil {
			outputs[0] = new(big.Int)
		}
		outputs[0].SetUint64(uint64(depth)) // sentinel
		if outputs[1] == nil {
			outputs[1] = new(big.Int)
		}
		outputs[1].SetUint64(1) // eqFlag = 1
		return nil
	}

	// keys differ
	xor := new(big.Int).Xor(oldKey, newKey)
	idx := xor.BitLen() - 1 // 0-based, LSB = 0

	if idx >= depth { // cannot differ above MSB of tree
		return fmt.Errorf("keys differ above tree depth (idx=%d, depth=%d)", idx, depth)
	}

	if outputs[0] == nil {
		outputs[0] = new(big.Int)
	}
	outputs[0].SetUint64(uint64(idx)) // differing bit index

	if outputs[1] == nil {
		outputs[1] = new(big.Int)
	}
	outputs[1].SetUint64(0) // eqFlag = 0
	return nil
}

// SiblingZerosHint takes a list of sibling hashes and outputs a list of flags (1 if sibling is zero, 0 otherwise).
func SiblingZerosHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// len(outputs) should equal len(inputs)
	if len(outputs) != len(inputs) {
		return fmt.Errorf("SiblingZerosHint: input and output lengths must match")
	}
	for i := range inputs {
		if inputs[i].Sign() == 0 {
			outputs[i] = big.NewInt(1) // zero -> flag 1
		} else {
			outputs[i] = big.NewInt(0) // non-zero -> flag 0
		}
	}
	return nil
}

// MultiInvZeroHint computes the modular inverse of each input element.
// If an input is zero, it sets the corresponding output to 1 (flag) and the inverse to 0.
func MultiInvZeroHint(q *big.Int, in, out []*big.Int) error {
	n := len(in)
	if len(out) != 2*n {
		return fmt.Errorf("need %d outputs, got %d", 2*n, len(out))
	}
	for i, s := range in {
		if s.Sign() == 0 {
			out[i] = big.NewInt(1)   // flag
			out[n+i] = big.NewInt(0) // inv
		} else {
			inv := new(big.Int).ModInverse(s, q)
			if inv == nil {
				return fmt.Errorf("no inverse")
			}
			out[i] = big.NewInt(0)
			out[n+i] = inv
		}
	}
	return nil
}
