package mimc7

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// maxInputs constant is the maximum number of inputs that the MiMC hash
// function can take. Experimentally, the maximum number of inputs is 62.
const maxInputs = 62

type MiMC struct {
	api    frontend.API
	params []frontend.Variable // slice containing constants for the encryption rounds
	h      frontend.Variable   // current vector in the Miyaguchi–Preneel scheme
	data   []frontend.Variable // state storage. data is updated when Write() is called. Sum sums the data.
}

// NewMiMC function returns a initialized MiMC hash function into the BabyJubJub
// curve for the BN254. WARNING: This function only works for the BN254 curve.
// If your circuit has not this curve as the native curve, you can use the
// emulated version of the MiMC hash function.
func NewMiMC(api frontend.API) (MiMC, error) {
	return MiMC{
		api:    api,
		params: constants,
		h:      frontend.Variable(0),
	}, nil
}

// Write adds more data to the running hash.
func (h *MiMC) Write(data ...frontend.Variable) error {
	if len(h.data)+len(data) > maxInputs {
		return fmt.Errorf("too many inputs. Max inputs is %d", maxInputs)
	}
	h.data = append(h.data, data...)
	return nil
}

// Reset resets the Hash to its initial state.
func (h *MiMC) Reset() {
	h.data = nil
	h.h = emulated.ValueOf[sw_bn254.ScalarField](nil)
}

// Sum hash using [Miyaguchi–Preneel] where the XOR operation is replaced by
// field addition.
func (h *MiMC) Sum() frontend.Variable {
	for _, stream := range h.data {
		r := h.encrypt(stream)
		h.h = h.api.Add(h.h, r, stream)
	}
	h.data = nil // flush the data already hashed
	return h.h
}

// AssertSumIsEqual asserts that the hash of the data is equal to the expected
// hash.
func (h *MiMC) AssertSumIsEqual(expected frontend.Variable) {
	flag := h.AssertSumIsEqualFlag(expected)
	h.api.AssertIsEqual(flag, 1)
}

// AssertSumIsEqualFlag returns a flag that is 1 if the hash of the data is
// equal to the expected hash and 0 otherwise.
func (h *MiMC) AssertSumIsEqualFlag(expected frontend.Variable) frontend.Variable {
	res := h.Sum()
	return h.api.IsZero(h.api.Sub(res, expected))
}

func (h *MiMC) MultiHash(inputs ...frontend.Variable) (frontend.Variable, error) {
	// if the number of inputs is less than maxInputs, we can use the MiMC hash
	// function directly
	if len(inputs) < maxInputs {
		if err := h.Write(inputs...); err != nil {
			return nil, err
		}
		return h.Sum(), nil
	} else if len(inputs)/maxInputs > maxInputs {
		return nil, fmt.Errorf("too many inputs.")
	}
	// calculate chunk hashes
	hashed := []frontend.Variable{}
	chunk := []frontend.Variable{}
	for _, input := range inputs {
		if len(chunk) == maxInputs {
			if err := h.Write(chunk...); err != nil {
				return nil, err
			}
			hashed = append(hashed, h.Sum())
			chunk = []frontend.Variable{}
			h.Reset()
		}
		chunk = append(chunk, input)
	}
	// if the final chunk is not empty, hash it to get the last chunk hash
	if len(chunk) > 0 {
		if err := h.Write(chunk...); err != nil {
			return nil, err
		}
		hashed = append(hashed, h.Sum())
		h.Reset()
	}
	// if there is only one chunk, return its hash
	if len(hashed) == 1 {
		return hashed[0], nil
	}
	// return the hash of all chunk hashes
	if err := h.Write(hashed...); err != nil {
		return nil, err
	}
	return h.Sum(), nil
}

func (h *MiMC) AssertMultiHashIsEqualFlag(expected frontend.Variable, inputs ...frontend.Variable) (frontend.Variable, error) {
	sum, err := h.MultiHash(inputs...)
	if err != nil {
		return 0, err
	}
	return h.api.IsZero(h.api.Sub(&sum, &expected)), nil
}

func (h *MiMC) AssertMultiHashIsEqual(expected frontend.Variable, inputs ...frontend.Variable) error {
	flag, err := h.AssertMultiHashIsEqualFlag(expected, inputs...)
	if err != nil {
		return err
	}
	h.api.AssertIsEqual(flag, 1)
	return nil
}

func (h *MiMC) pow7(x frontend.Variable) frontend.Variable {
	x2 := h.api.Mul(x, x)
	x3 := h.api.Mul(x2, x)
	x5 := h.api.Mul(x2, x3)
	return h.api.Mul(x2, x5)
}

func (h *MiMC) encrypt(m frontend.Variable) frontend.Variable {
	x := m
	for i := range nRounds {
		sum := h.api.Add(x, h.h, h.params[i])
		x = h.pow7(sum)
	}
	return h.api.Add(x, h.h)
}
