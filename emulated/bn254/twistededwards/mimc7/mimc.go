package mimc7

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type MiMC struct {
	params []emulated.Element[sw_bn254.ScalarField] // slice containing constants for the encryption rounds
	h      emulated.Element[sw_bn254.ScalarField]   // current vector in the Miyaguchi–Preneel scheme
	data   []emulated.Element[sw_bn254.ScalarField] // state storage. data is updated when Write() is called. Sum sums the data.
	field  *emulated.Field[sw_bn254.ScalarField]
}

// NewMiMC function returns a initialized MiMC hash function into the BabyJubJub
// curve for the emulated BN254 ScalarField.
func NewMiMC(api frontend.API) (MiMC, error) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return MiMC{}, err
	}
	return MiMC{
		params: constants,
		h:      emulated.ValueOf[sw_bn254.ScalarField](nil),
		field:  field,
	}, nil
}

// Write adds more data to the running hash.
func (h *MiMC) Write(data ...emulated.Element[sw_bn254.ScalarField]) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *MiMC) Reset() {
	h.data = nil
	h.h = emulated.ValueOf[sw_bn254.ScalarField](nil)
}

// Sum hash using [Miyaguchi–Preneel] where the XOR operation is replaced by
// field addition.
func (h *MiMC) Sum() emulated.Element[sw_bn254.ScalarField] {
	for _, stream := range h.data {
		r := h.encrypt(stream)
		h.h = *h.field.Add(&h.h, &r)
		h.h = *h.field.ModAdd(&h.h, &stream, &q)
	}
	h.data = nil // flush the data already hashed
	return h.h
}

// AssertSumIsEqual asserts that the hash of the data is equal to the expected
// hash.
func (h *MiMC) AssertSumIsEqual(expected emulated.Element[sw_bn254.ScalarField]) {
	res := h.Sum()
	h.field.AssertIsEqual(&res, &expected)
}

func (h *MiMC) pow7(x emulated.Element[sw_bn254.ScalarField]) emulated.Element[sw_bn254.ScalarField] {
	x2 := h.field.Mul(&x, &x)
	x3 := h.field.Mul(x2, &x)
	x5 := h.field.Mul(x2, x3)
	return *h.field.Mul(x2, x5)
}

func (h *MiMC) encrypt(m emulated.Element[sw_bn254.ScalarField]) emulated.Element[sw_bn254.ScalarField] {
	x := m
	for i := 0; i < nRounds; i++ {
		sum := h.field.Add(&x, &h.h)
		sum = h.field.Add(sum, &h.params[i])
		x = h.pow7(*sum)
	}
	return *h.field.Add(&x, &h.h)
}