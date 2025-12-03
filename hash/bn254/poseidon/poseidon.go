package poseidon

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// MaxMultihashInputs defines the maximum number of inputs supported by the MultiHash function.
const MaxMultihashInputs = 4096

// Poseidon struct represents a Poseidon hash function object that can be used
// to hash inputs. The Poseidon hash function is a cryptographic hash function
// that is designed to be efficient in terms of both time and space. It is
// based on the Merkle-Damgård construction and uses a sponge construction
// with a permutation that is based on the Poseidon permutation. The Poseidon
// permutation is a round-based permutation that uses a series of operations
// to mix the input data and produce the output hash. The Poseidon hash
// function is designed to be resistant to various cryptographic attacks,
// including differential and linear cryptanalysis, and is suitable for use
// in a wide range of applications, including blockchain and cryptocurrency
// systems.
type Poseidon struct {
	api  frontend.API
	data []frontend.Variable
}

// Hash returns the hash of the provided inputs using the Poseidon hash
// function. This function supports up to 16 inputs. If more than 16 inputs
// are provided, it will return an error. If the number of inputs is 16 or less,
// it will return the hash of the inputs. This function is equivalent to calling
// NewPoseidon and then calling Write and Sum on the returned Poseidon object.
func Hash(api frontend.API, inputs ...frontend.Variable) (frontend.Variable, error) {
	h := NewPoseidon(api)
	if err := h.Write(inputs...); err != nil {
		return 0, err
	}
	return h.Sum(), nil
}

// MultiHash returns the hash of the provided inputs using the Poseidon hash
// function. This function supports up to MaxMultihashInputs inputs. If more
// are provided, it will return an error. If the number of inputs is 16 or
// less, it will return the result of Hash function. If the number of inputs
// is greater than 16, it will calculate the hash of the inputs by dividing
// them into chunks of 16 inputs each, hashing each chunk, and then hashing
// the resulting chunk hashes.
func MultiHash(api frontend.API, inputs ...frontend.Variable) (frontend.Variable, error) {
	if l := len(inputs); l <= 16 {
		return Hash(api, inputs...)
	} else if l > MaxMultihashInputs {
		return 0, fmt.Errorf("the maximum number of inputs supported is %d", MaxMultihashInputs)
	}

	// Pre-calculate number of chunks for memory efficiency
	numChunks := (len(inputs) + 15) / 16 // ceiling division
	hashed := make([]frontend.Variable, 0, numChunks)
	hasher := NewPoseidon(api)

	// Process inputs in 16-element chunks using slice operations
	for i := 0; i < len(inputs); i += 16 {
		end := min(i+16, len(inputs))

		// Hash the chunk
		if err := hasher.Write(inputs[i:end]...); err != nil {
			return 0, err
		}
		hashed = append(hashed, hasher.Sum())
		hasher.Reset()
	}

	// Single chunk case - return directly
	if len(hashed) == 1 {
		return hashed[0], nil
	}

	// Multiple chunks - recursively hash chunk hashes if needed
	// If we have more than 16 chunk hashes, we need to recursively apply MegaHash
	if len(hashed) <= 16 {
		if err := hasher.Write(hashed...); err != nil {
			return 0, err
		}
		return hasher.Sum(), nil
	}

	// Recursively hash the chunk hashes
	return MultiHash(api, hashed...)
}

// NewPoseidon returns a new Poseidon object that can be used to hash inputs.
func NewPoseidon(api frontend.API) Poseidon {
	return Poseidon{
		api:  api,
		data: []frontend.Variable{},
	}
}

// Write adds the provided inputs to the Poseidon object. If the number of
// inputs is greater than 16, it will return an error.
func (h *Poseidon) Write(data ...frontend.Variable) error {
	if len(h.data)+len(data) > 16 {
		return fmt.Errorf("poseidon hash only supports up to 16 inputs, use MultiHash instead")
	}
	h.data = append(h.data, data...)
	return nil
}

// Reset resets the Poseidon object, removing all written inputs.
func (h *Poseidon) Reset() {
	h.data = []frontend.Variable{}
}

// Sum returns the hash of the inputs written to the Poseidon object.
func (h *Poseidon) Sum() frontend.Variable {
	nInputs := len(h.data)
	// and rounded up to nearest integer that divides by t
	nRoundsPC := [16]int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}
	t := nInputs + 1
	nRoundsF := 8
	nRoundsP := nRoundsPC[t-2]
	c := getConstant(C, t)
	s := getConstant(S, t)
	m := getConstant(M, t)
	p := getConstant(P, t)

	state := make([]frontend.Variable, t)
	for j := range t {
		if j == 0 {
			state[0] = 0
		} else {
			state[j] = h.data[j-1]
		}
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
		state[0] = h.api.Add(state[0], c[(nRoundsF/2+1)*t+r])
		newState0 := frontend.Variable(0)
		for j := 0; j < len(state); j++ {
			mul := h.api.Mul(s[(t*2-1)*r+j], state[j])
			newState0 = h.api.Add(newState0, mul)
		}

		for k := 1; k < t; k++ {
			state[k] = h.api.Add(state[k], h.api.Mul(state[0], s[(t*2-1)*r+t+k-1]))
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
	h.data = []frontend.Variable{}
	return out
}

func (h *Poseidon) sigma(in frontend.Variable) frontend.Variable {
	in2 := h.api.Mul(in, in)
	in4 := h.api.Mul(in2, in2)
	return h.api.Mul(in4, in)
}

func (h *Poseidon) ark(in []frontend.Variable, c []*big.Int, r int) []frontend.Variable {
	out := make([]frontend.Variable, len(in))
	for i, v := range in {
		out[i] = h.api.Add(v, c[i+r])
	}
	return out
}

func (h *Poseidon) mix(in []frontend.Variable, m [][]*big.Int) []frontend.Variable {
	t := len(in)
	out := make([]frontend.Variable, t)
	for i := range t {
		lc := frontend.Variable(0)
		for j := range t {
			lc = h.api.Add(lc, h.api.Mul(m[j][i], in[j]))
		}
		out[i] = lc
	}
	return out
}

func (h *Poseidon) mixLast(in []frontend.Variable, m [][]*big.Int, s int) frontend.Variable {
	t := len(in)
	out := frontend.Variable(0)
	for j := range t {
		out = h.api.Add(out, h.api.Mul(m[j][s], in[j]))
	}
	return out
}
