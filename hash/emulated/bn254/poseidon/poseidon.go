package poseidon

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

const (
	// MaxMultihashInputs defines the maximum number of inputs supported by the MultiHash function.
	MaxMultihashInputs = 4096
	// MaxHashInputs defines the maximum number of inputs supported by the Hash function.
	MaxHashInputs = 16
)

// Poseidon over emulated BN254 scalar field, usable inside foreign-curve circuits (e.g., BLS12-377).
type Poseidon struct {
	api   frontend.API
	field *emulated.Field[sw_bn254.ScalarField]
	data  []emulated.Element[sw_bn254.ScalarField]
}

// New builds a new hasher.
func New(api frontend.API) (*Poseidon, error) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return nil, err
	}
	return &Poseidon{
		api:   api,
		field: field,
		data:  []emulated.Element[sw_bn254.ScalarField]{},
	}, nil
}

// Write buffers inputs; rate is 16.
func (h *Poseidon) Write(data ...emulated.Element[sw_bn254.ScalarField]) {
	if len(h.data)+len(data) > MaxHashInputs {
		return
	}
	h.data = append(h.data, data...)
}

// Reset clears buffered inputs.
func (h *Poseidon) Reset() {
	h.data = []emulated.Element[sw_bn254.ScalarField]{}
}

// Sum computes the hash of buffered inputs.
func (h *Poseidon) Sum() emulated.Element[sw_bn254.ScalarField] {
	nInputs := len(h.data)
	nRoundsPC := [16]int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}
	t := nInputs + 1
	nRoundsF := 8
	nRoundsP := nRoundsPC[t-2]
	c := getConstant(C, t)
	s := getConstant(S, t)
	m := getConstant(M, t)
	p := getConstant(P, t)

	state := make([]*emulated.Element[sw_bn254.ScalarField], t)
	state[0] = h.field.NewElement(big.NewInt(0))
	for j := 1; j < t; j++ {
		state[j] = h.field.NewElement(h.data[j-1])
	}
	state = h.ark(state, c, 0)

	for r := 0; r < nRoundsF/2-1; r++ {
		for j := range t {
			state[j] = h.sigma(state[j])
		}
		state = h.ark(state, c, (r+1)*t)
		state = h.mix(state, m)
	}

	for j := range t {
		state[j] = h.sigma(state[j])
	}
	state = h.ark(state, c, nRoundsF/2*t)
	state = h.mix(state, p)

	for r := range nRoundsP {
		state[0] = h.sigma(state[0])
		state[0] = h.field.Add(state[0], constElement(h.field, c[(nRoundsF/2+1)*t+r]))

		newState0 := h.field.Zero()
		for j := 0; j < len(state); j++ {
			newState0 = h.field.Add(newState0, h.field.Mul(constElement(h.field, s[(t*2-1)*r+j]), state[j]))
		}

		for k := 1; k < t; k++ {
			state[k] = h.field.Add(state[k], h.field.Mul(state[0], constElement(h.field, s[(t*2-1)*r+t+k-1])))
		}
		state[0] = newState0
	}

	for r := 0; r < nRoundsF/2-1; r++ {
		for j := range t {
			state[j] = h.sigma(state[j])
		}
		state = h.ark(state, c, (nRoundsF/2+1)*t+nRoundsP+r*t)
		state = h.mix(state, m)
	}

	for j := range t {
		state[j] = h.sigma(state[j])
	}

	out := h.mixLast(state, m, 0)
	h.data = []emulated.Element[sw_bn254.ScalarField]{}
	return *out
}

func (h *Poseidon) WriteSucceeded() bool {
	return len(h.data) > 0
}

func (h *Poseidon) SumIsEqual(expected emulated.Element[sw_bn254.ScalarField]) frontend.Variable {
	res := h.Sum()
	return h.field.IsZero(h.field.Sub(&res, &expected))
}

func (h *Poseidon) AssertSumIsEqual(expected emulated.Element[sw_bn254.ScalarField]) {
	flag := h.SumIsEqual(expected)
	h.api.AssertIsEqual(flag, 1)
}

func (h *Poseidon) sigma(in *emulated.Element[sw_bn254.ScalarField]) *emulated.Element[sw_bn254.ScalarField] {
	in2 := h.field.Mul(in, in)
	in4 := h.field.Mul(in2, in2)
	return h.field.Mul(in4, in)
}

func (h *Poseidon) ark(in []*emulated.Element[sw_bn254.ScalarField], c []*big.Int, r int) []*emulated.Element[sw_bn254.ScalarField] {
	out := make([]*emulated.Element[sw_bn254.ScalarField], len(in))
	for i, v := range in {
		out[i] = h.field.Add(v, constElement(h.field, c[i+r]))
	}
	return out
}

func (h *Poseidon) mix(in []*emulated.Element[sw_bn254.ScalarField], m [][]*big.Int) []*emulated.Element[sw_bn254.ScalarField] {
	t := len(in)
	out := make([]*emulated.Element[sw_bn254.ScalarField], t)
	for i := range t {
		sum := h.field.Zero()
		for j := range t {
			sum = h.field.Add(sum, h.field.Mul(constElement(h.field, m[j][i]), in[j]))
		}
		out[i] = sum
	}
	return out
}

func (h *Poseidon) mixLast(in []*emulated.Element[sw_bn254.ScalarField], m [][]*big.Int, r int) *emulated.Element[sw_bn254.ScalarField] {
	t := len(in)
	out := h.field.Zero()
	for j := range t {
		out = h.field.Add(out, h.field.Mul(constElement(h.field, m[j][r]), in[j]))
	}
	return out
}

func constElement(f *emulated.Field[sw_bn254.ScalarField], bi *big.Int) *emulated.Element[sw_bn254.ScalarField] {
	return f.NewElement(bi)
}

// Hash computes a Poseidon hash over emulated BN254 elements.
func Hash(api frontend.API, inputs ...emulated.Element[sw_bn254.ScalarField]) (emulated.Element[sw_bn254.ScalarField], error) {
	h, err := New(api)
	if err != nil {
		return emulated.Element[sw_bn254.ScalarField]{}, err
	}
	h.Write(inputs...)
	return h.Sum(), nil
}

// MultiHash hashes up to MaxMultihashInputs elements by chunking with rate 16, mirroring the native gadget.
func MultiHash(api frontend.API, inputs ...emulated.Element[sw_bn254.ScalarField]) (emulated.Element[sw_bn254.ScalarField], error) {
	if l := len(inputs); l <= 16 {
		return Hash(api, inputs...)
	} else if l > MaxMultihashInputs {
		return emulated.Element[sw_bn254.ScalarField]{}, fmt.Errorf("the maximum number of inputs supported is %d", MaxMultihashInputs)
	}

	numChunks := (len(inputs) + 15) / 16
	hashed := make([]emulated.Element[sw_bn254.ScalarField], 0, numChunks)
	h, err := New(api)
	if err != nil {
		return emulated.Element[sw_bn254.ScalarField]{}, err
	}

	for i := 0; i < len(inputs); i += 16 {
		end := min(i+16, len(inputs))
		h.Write(inputs[i:end]...)
		hashed = append(hashed, h.Sum())
		h.Reset()
	}

	if len(hashed) == 1 {
		return hashed[0], nil
	}

	if len(hashed) <= 16 {
		h.Write(hashed...)
		return h.Sum(), nil
	}
	return MultiHash(api, hashed...)
}

// AssertMultiHashEqual computes a Poseidon multihash of inputs and asserts it matches expected.
func AssertMultiHashEqual(api frontend.API, inputs []emulated.Element[sw_bn254.ScalarField], expected emulated.Element[sw_bn254.ScalarField]) error {
	res, err := MultiHash(api, inputs...)
	if err != nil {
		return fmt.Errorf("poseidon multihash: %w", err)
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("poseidon field: %w", err)
	}
	field.AssertIsEqual(&res, &expected)
	return nil
}
