package mimc

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"
	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/mimc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// MiMC contains the params of the MiMC hash func and the curves on which it is implemented.
//
// NB! See the package documentation for length extension attack consideration.
type MiMC[T emulated.FieldParams] struct {
	params []emulated.Element[T] // slice containing constants for the encryption rounds
	id     ecc.ID                // id needed to know which encryption function to use
	h      emulated.Element[T]   // current vector in the Miyaguchi–Preneel scheme
	data   []emulated.Element[T] // state storage. data is updated when Write() is called. Sum sums the data.
	field  *emulated.Field[T]    // underlying constraint system

	encryptFn func(emulated.Element[T]) emulated.Element[T]
}

// NewMiMC returns a MiMC instance that can be used in a gnark circuit. The
// out-circuit counterpart of this function is provided in [gnark-crypto].
//
// NB! See the package documentation for length extension attack consideration.
//
// [gnark-crypto]: https://pkg.go.dev/github.com/consensys/gnark-crypto/hash
func NewMiMC[T emulated.FieldParams](api frontend.API, id ecc.ID) (MiMC[T], error) {
	// init the field
	field, err := emulated.NewField[T](api)
	if err != nil {
		return MiMC[T]{}, err
	}
	// init the MiMC instance based on the curve id
	res := MiMC[T]{
		field: field,
		id:    id,
		h:     emulated.ValueOf[T](0),
	}
	switch id {
	case ecc.BN254:
		res.params = constantsToField[T](bn254.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow5(res, e)
		}
	case ecc.BLS12_377:
		res.params = constantsToField[T](bls12377.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow17(res, e)
		}
	case ecc.BLS12_381:
		res.params = constantsToField[T](bls12381.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow5(res, e)
		}
	case ecc.BW6_633:
		res.params = constantsToField[T](bw6633.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow5(res, e)
		}
	case ecc.BW6_761:
		res.params = constantsToField[T](bw6761.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow5(res, e)
		}
	case ecc.BLS24_315:
		res.params = constantsToField[T](bls24315.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow5(res, e)
		}
	case ecc.BLS24_317:
		res.params = constantsToField[T](bls24317.GetConstants())
		res.encryptFn = func(e emulated.Element[T]) emulated.Element[T] {
			return encryptPow7(res, e)
		}
	default:
		return res, errors.New("unknown curve id")
	}
	return res, nil
}

// Write adds more data to the running hash.
func (h *MiMC[T]) Write(data ...emulated.Element[T]) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *MiMC[T]) Reset() {
	h.data = nil
	h.h = emulated.ValueOf[T](0)
}

// SetState manually sets the state of the hasher to the provided value. In the
// case of MiMC only a single frontend variable is expected to represent the
// state.
func (h *MiMC[T]) SetState(newState []emulated.Element[T]) error {
	if len(h.data) > 0 {
		return errors.New("the hasher is not in an initial state")
	}
	if len(newState) != 1 {
		return errors.New("the MiMC hasher expects a single field element to represent the state")
	}
	h.h = newState[0]
	h.data = nil
	return nil
}

// State returns the inner-state of the hasher. In the context of MiMC only a
// single field element is returned.
func (h *MiMC[T]) State() []emulated.Element[T] {
	h.Sum() // this flushes the unsummed data
	return []emulated.Element[T]{h.h}
}

// Sum hash using [Miyaguchi–Preneel] where the XOR operation is replaced by
// field addition.
//
// [Miyaguchi–Preneel]: https://en.wikipedia.org/wiki/One-way_compression_function
func (h *MiMC[T]) Sum() emulated.Element[T] {
	for _, stream := range h.data {
		r := h.encryptFn(stream)
		h.h = *h.field.Add(&h.h, &r)
	}
	h.data = nil // flush the data already hashed
	return h.h

}
