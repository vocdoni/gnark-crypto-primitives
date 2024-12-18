package twistededwards

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/format"
)

type testFromTwistedEdwards struct {
	X, Y, XPrime, YPrime frontend.Variable
}

func (c *testFromTwistedEdwards) Define(api frontend.API) error {
	xPrime, yPrime := FromTEtoRTE(api, c.X, c.Y)
	api.AssertIsEqual(xPrime, c.XPrime)
	api.AssertIsEqual(yPrime, c.YPrime)
	return nil
}

type testToTwistedEdwards struct {
	X, Y, XPrime, YPrime frontend.Variable
}

func (c *testToTwistedEdwards) Define(api frontend.API) error {
	xPrime, yPrime := FromRTEtoTE(api, c.X, c.Y)
	api.AssertIsEqual(xPrime, c.XPrime)
	api.AssertIsEqual(yPrime, c.YPrime)
	return nil
}

func TestFromTwistedEdwards(t *testing.T) {
	x, _ := new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	y, _ := new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)

	xRTE, yRTE := format.FromTEtoRTE(x, y)
	// profiling the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testFromTwistedEdwards{})
	fmt.Println("From TwistedEdwards to Reduced TwistedEdwards compilation")
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// run the test circuit
	assert := test.NewAssert(t)
	inputs := &testFromTwistedEdwards{
		X:      x,
		Y:      y,
		XPrime: xRTE,
		YPrime: yRTE,
	}
	now = time.Now()
	assert.SolvingSucceeded(&testFromTwistedEdwards{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	fmt.Println("elapsed", time.Since(now))
}

func TestFromReducedTwistedEdwards(t *testing.T) {
	x, _ := new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	y, _ := new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)

	xRTE, yRTE := format.FromTEtoRTE(x, y)
	// profiling the circuit compilation
	p := profile.Start()
	now := time.Now()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testToTwistedEdwards{})
	fmt.Println("From Reduced TwistedEdwards to Reduced TwistedEdwards compilation")
	fmt.Println("elapsed", time.Since(now))
	p.Stop()
	fmt.Println("constrains", p.NbConstraints())
	// run the test circuit
	assert := test.NewAssert(t)
	inputs := &testToTwistedEdwards{
		X:      xRTE,
		Y:      yRTE,
		XPrime: x,
		YPrime: y,
	}
	assert.SolvingSucceeded(&testToTwistedEdwards{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
