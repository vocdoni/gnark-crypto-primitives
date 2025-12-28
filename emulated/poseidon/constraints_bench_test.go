package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// helper circuit that performs 26 emulated Poseidon hashes (3 inputs each).
type manyHashesCircuit struct {
	Inputs [10][3]emulated.Element[sw_bn254.ScalarField]
}

func (c *manyHashesCircuit) Define(api frontend.API) error {
	for i := 0; i < 10; i++ {
		if _, err := Hash(api, c.Inputs[i][0], c.Inputs[i][1], c.Inputs[i][2]); err != nil {
			return err
		}
	}
	return nil
}

// TestConstraintCount26Hashes compiles on BLS12-377 and logs the constraint count for 26 emulated hashes.
func TestConstraintCount26Hashes(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &manyHashesCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Constraints for 10 emulated BN254 Poseidon hashes on BLS12-377: %d", ccs.GetNbConstraints())
}
