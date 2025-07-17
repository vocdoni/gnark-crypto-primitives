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
	field  *emulated.Field[sw_bn254.ScalarField]
	params []emulated.Element[sw_bn254.ScalarField] // slice containing constants for the encryption rounds
	h      emulated.Element[sw_bn254.ScalarField]   // current vector in the Miyaguchi–Preneel scheme
	data   []emulated.Element[sw_bn254.ScalarField] // state storage. data is updated when Write() is called. Sum sums the data.
}

// NewMiMC function returns a initialized MiMC hash function into the BabyJubJub
// curve for the emulated BN254 ScalarField.
func NewMiMC(api frontend.API) (MiMC, error) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return MiMC{}, err
	}
	return MiMC{
		api:    api,
		field:  field,
		params: constants,
		h:      emulated.ValueOf[sw_bn254.ScalarField](nil),
	}, nil
}

// Write adds more data to the running hash.
func (h *MiMC) Write(data ...emulated.Element[sw_bn254.ScalarField]) error {
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
	flag := h.AssertSumIsEqualFlag(expected)
	h.api.AssertIsEqual(flag, 1)
}

// AssertSumIsEqualFlag returns a flag that is 1 if the hash of the data is
// equal to the expected hash and 0 otherwise.
func (h *MiMC) AssertSumIsEqualFlag(expected emulated.Element[sw_bn254.ScalarField]) frontend.Variable {
	res := h.Sum()
	return h.field.IsZero(h.field.Sub(&res, &expected))
}

func (h *MiMC) pow7(x emulated.Element[sw_bn254.ScalarField]) emulated.Element[sw_bn254.ScalarField] {
	x2 := h.field.Mul(&x, &x)
	x3 := h.field.Mul(x2, &x)
	x5 := h.field.Mul(x2, x3)
	return *h.field.Mul(x2, x5)
}

func (h *MiMC) encrypt(m emulated.Element[sw_bn254.ScalarField]) emulated.Element[sw_bn254.ScalarField] {
	x := m
	for i := range nRounds {
		sum := h.field.Add(&x, &h.h)
		sum = h.field.Add(sum, &h.params[i])
		x = h.pow7(*sum)
	}
	return *h.field.Add(&x, &h.h)
}
