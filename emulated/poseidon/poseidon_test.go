package poseidon

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type hashCircuit struct {
	Inputs   [3]emulated.Element[sw_bn254.ScalarField]
	Expected emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *hashCircuit) Define(api frontend.API) error {
	out, err := Hash(api, c.Inputs[0], c.Inputs[1], c.Inputs[2])
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	field.AssertIsEqual(&out, &c.Expected)
	return nil
}

func TestEmulatedPoseidonMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)

	// reference inputs
	var a, b, c bn254fr.Element
	a.SetUint64(1)
	b.SetUint64(2)
	c.SetUint64(3)
	expected := referenceHash(a, b, c)

	witness := hashCircuit{
		Inputs: [3]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](a.BigInt(new(big.Int))),
			emulated.ValueOf[sw_bn254.ScalarField](b.BigInt(new(big.Int))),
			emulated.ValueOf[sw_bn254.ScalarField](c.BigInt(new(big.Int))),
		},
		Expected: emulated.ValueOf[sw_bn254.ScalarField](expected.BigInt(new(big.Int))),
	}

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &hashCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("emulated bn254 poseidon constraints (bls12-377 host): %d", ccs.GetNbConstraints())

	assert.ProverSucceeded(
		&hashCircuit{},
		&witness,
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
	)
}

// referenceHash mirrors the permutation using bn254 native field constants.
func referenceHash(inputs ...bn254fr.Element) bn254fr.Element {
	nInputs := len(inputs)
	nRoundsPC := [16]int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}
	t := nInputs + 1
	nRoundsF := 8
	nRoundsP := nRoundsPC[t-2]
	c := getConstant(C, t) // []*big.Int
	s := getConstant(S, t) // []*big.Int
	m := getConstant(M, t) // [][]*big.Int
	p := getConstant(P, t) // [][]*big.Int

	state := make([]bn254fr.Element, t)
	for j := 0; j < t; j++ {
		if j == 0 {
			state[0].SetZero()
		} else {
			state[j] = inputs[j-1]
		}
	}
	arkNative(state, c, 0)

	for r := 0; r < nRoundsF/2-1; r++ {
		for j := 0; j < t; j++ {
			sigmaNative(&state[j])
		}
		arkNative(state, c, (r+1)*t)
		mixNative(state, m)
	}

	for j := 0; j < t; j++ {
		sigmaNative(&state[j])
	}
	arkNative(state, c, nRoundsF/2*t)
	mixPartialNative(state, p)

	for r := 0; r < nRoundsP; r++ {
		sigmaNative(&state[0])
		var tmp bn254fr.Element
		tmp.SetBigInt(c[(nRoundsF/2+1)*t+r])
		state[0].Add(&state[0], &tmp)

		mulResults := make([]bn254fr.Element, len(state))
		for j := 0; j < len(state); j++ {
			var coeff bn254fr.Element
			coeff.SetBigInt(s[(t*2-1)*r+j])
			mulResults[j].Mul(&coeff, &state[j])
		}
		var newState0 bn254fr.Element
		for _, v := range mulResults {
			newState0.Add(&newState0, &v)
		}

		for k := 1; k < t; k++ {
			var coeff bn254fr.Element
			coeff.SetBigInt(s[(t*2-1)*r+t+k-1])
			var mul bn254fr.Element
			mul.Mul(&state[0], &coeff)
			state[k].Add(&state[k], &mul)
		}
		state[0] = newState0
	}

	for r := 0; r < nRoundsF/2-1; r++ {
		for j := 0; j < t; j++ {
			sigmaNative(&state[j])
		}
		arkNative(state, c, (nRoundsF/2+1)*t+nRoundsP+r*t)
		mixNative(state, m)
	}

	for j := 0; j < t; j++ {
		sigmaNative(&state[j])
	}

	return mixLastNative(state, m, 0)
}

func sigmaNative(in *bn254fr.Element) {
	var in2, in4 bn254fr.Element
	in2.Mul(in, in)
	in4.Mul(&in2, &in2)
	in.Mul(&in4, in)
}

func arkNative(state []bn254fr.Element, c []*big.Int, r int) {
	for i := range state {
		var tmp bn254fr.Element
		tmp.SetBigInt(c[i+r])
		state[i].Add(&state[i], &tmp)
	}
}

func mixNative(state []bn254fr.Element, m [][]*big.Int) {
	t := len(state)
	out := make([]bn254fr.Element, t)
	for i := 0; i < t; i++ {
		var sum bn254fr.Element
		for j := 0; j < t; j++ {
			var coeff bn254fr.Element
			coeff.SetBigInt(m[j][i])
			var mul bn254fr.Element
			mul.Mul(&coeff, &state[j])
			sum.Add(&sum, &mul)
		}
		out[i] = sum
	}
	copy(state, out)
}

func mixPartialNative(state []bn254fr.Element, p [][]*big.Int) {
	t := len(state)
	out := make([]bn254fr.Element, t)
	for i := 0; i < t; i++ {
		var sum bn254fr.Element
		for j := 0; j < t; j++ {
			var coeff bn254fr.Element
			coeff.SetBigInt(p[j][i])
			var mul bn254fr.Element
			mul.Mul(&coeff, &state[j])
			sum.Add(&sum, &mul)
		}
		out[i] = sum
	}
	copy(state, out)
}

func mixLastNative(state []bn254fr.Element, m [][]*big.Int, r int) bn254fr.Element {
	t := len(state)
	var out bn254fr.Element
	for j := 0; j < t; j++ {
		var coeff bn254fr.Element
		coeff.SetBigInt(m[j][r])
		var mul bn254fr.Element
		mul.Mul(&coeff, &state[j])
		out.Add(&out, &mul)
	}
	return out
}
