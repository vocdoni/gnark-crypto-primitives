package arbo

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestValidSiblings(t *testing.T) {
	c := qt.New(t)
	// empty results
	c.Assert(ValidSiblings(nil, []*big.Int{big.NewInt(10)}, make([]*big.Int, 0)), qt.IsNotNil)
	// len(results) < nsiblings
	c.Assert(ValidSiblings(nil, []*big.Int{big.NewInt(10)}, make([]*big.Int, 9)), qt.IsNotNil)
	// valid inputs
	res := make([]*big.Int, 20)
	for i := range res {
		res[i] = new(big.Int)
	}
	c.Assert(ValidSiblings(nil, []*big.Int{big.NewInt(10)}, res), qt.IsNil)
	for i, v := range res {
		if i < 10 {
			c.Assert(v.Cmp(big.NewInt(1)), qt.Equals, 0)
		} else {
			c.Assert(v.Cmp(big.NewInt(0)), qt.Equals, 0)
		}
	}
}
