package poseidon2

import (
	"fmt"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/std/permutation/poseidon2"
)

func init() { solver.RegisterHint(MinMaxHint) }

// HashPoseidon2Gnark hashes 2- or 3-element tuples with Poseidon-2.
//
//	· internal node : H(min , max)
//	· leaf          : H(key , value , flag)
func HashPoseidon2Gnark(api frontend.API, limbs ...frontend.Variable) (frontend.Variable, error) {

	// off-circuit ordering for the 2-input case
	if len(limbs) == 2 {
		ord, err := api.NewHint(MinMaxHint, 2, limbs[0], limbs[1]) // [min,max]
		if err != nil {
			return 0, err
		}
		api.AssertIsLessOrEqual(ord[0], ord[1]) // min ≤ max
		limbs = ord
	}

	if n := len(limbs); n != 2 && n != 3 {
		return 0, fmt.Errorf("poseidon2: need 2 or 3 limbs, got %d", n)
	}

	// width-2 Poseidon-2 permutation (t=2, rF=6, rP=50)
	perm, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return 0, err
	}

	cv := frontend.Variable(0) // CV₀ := 0
	for _, m := range limbs {
		state := []frontend.Variable{cv, m} // absorb one limb
		if err := perm.Permutation(state); err != nil {
			return 0, err
		}
		cv = api.Add(state[1], m) // CVᵢ₊₁ = S₁ + mᵢ
	}
	return cv, nil
}
