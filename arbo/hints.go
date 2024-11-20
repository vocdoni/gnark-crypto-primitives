package arbo

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(replaceSiblingHint)
}

// replaceSiblingHint gnark hint function receives the new sibling to set as
// first input, the index of the sibling to be replaced as second input, and the
// rest of the siblings as the rest of the inputs. The function should return
// the new siblings with the replacement done.
func replaceSiblingHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != len(outputs)+2 {
		return fmt.Errorf("invalid number of inputs/outputs")
	}
	// get the new sibling and the index to replace
	newSibling := inputs[0]
	index := int(inputs[1].Int64())
	if index >= len(outputs) {
		return fmt.Errorf("invalid index")
	}
	siblings := inputs[2:]
	if len(siblings) != len(outputs) {
		return fmt.Errorf("invalid number of siblings")
	}
	for i := 0; i < len(outputs); i++ {
		if i == index {
			outputs[i] = outputs[i].Set(newSibling)
		} else {
			outputs[i] = outputs[i].Set(siblings[i])
		}
	}
	return nil
}
