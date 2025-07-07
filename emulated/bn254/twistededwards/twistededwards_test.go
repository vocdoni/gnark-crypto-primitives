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
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
)

type testFromTwistedEdwards struct {
	X, Y, XPrime, YPrime frontend.Variable

	EX, EY, EXPrime, EYPrime emulated.Element[sw_bn254.ScalarField]
}

func (c *testFromTwistedEdwards) Define(api frontend.API) error {
	xPrime, yPrime := FromTEtoRTE(api, c.X, c.Y)
	api.AssertIsEqual(xPrime, c.XPrime)
	api.AssertIsEqual(yPrime, c.YPrime)

	EXPrime, EYPrime, err := FromEmulatedTEtoRTE(api, c.EX, c.EY)
	if err != nil {
		return err
	}

	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	field.AssertIsEqual(&EXPrime, &c.EXPrime)
	field.AssertIsEqual(&EYPrime, &c.EYPrime)
	return nil
}

type testToTwistedEdwards struct {
	X, Y, XPrime, YPrime frontend.Variable

	EX, EY, EXPrime, EYPrime emulated.Element[sw_bn254.ScalarField]
}

func (c *testToTwistedEdwards) Define(api frontend.API) error {
	xPrime, yPrime := FromRTEtoTE(api, c.X, c.Y)
	api.AssertIsEqual(xPrime, c.XPrime)
	api.AssertIsEqual(yPrime, c.YPrime)

	EXPrime, EYPrime, err := FromEmulatedRTEtoTE(api, c.EX, c.EY)
	if err != nil {
		return err
	}

	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	field.AssertIsEqual(&EXPrime, &c.EXPrime)
	field.AssertIsEqual(&EYPrime, &c.EYPrime)
	return nil
}

func TestFromTwistedEdwards(t *testing.T) {
	x, _ := new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	eX := emulated.ValueOf[sw_bn254.ScalarField](x)
	y, _ := new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)
	eY := emulated.ValueOf[sw_bn254.ScalarField](y)

	xRTE, yRTE := format.FromTEtoRTE(x, y)
	eXRTE := emulated.ValueOf[sw_bn254.ScalarField](xRTE)
	eYRTE := emulated.ValueOf[sw_bn254.ScalarField](yRTE)
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
		X:       x,
		Y:       y,
		XPrime:  xRTE,
		YPrime:  yRTE,
		EX:      eX,
		EY:      eY,
		EXPrime: eXRTE,
		EYPrime: eYRTE,
	}
	now = time.Now()
	assert.SolvingSucceeded(&testFromTwistedEdwards{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	fmt.Println("elapsed", time.Since(now))
}

func TestFromReducedTwistedEdwards(t *testing.T) {
	x, _ := new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	ex := emulated.ValueOf[sw_bn254.ScalarField](x)
	y, _ := new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)
	ey := emulated.ValueOf[sw_bn254.ScalarField](y)

	xRTE, yRTE := format.FromTEtoRTE(x, y)
	exRTE := emulated.ValueOf[sw_bn254.ScalarField](xRTE)
	eyRTE := emulated.ValueOf[sw_bn254.ScalarField](yRTE)
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
		X:       xRTE,
		Y:       yRTE,
		XPrime:  x,
		YPrime:  y,
		EX:      exRTE,
		EY:      eyRTE,
		EXPrime: ex,
		EYPrime: ey,
	}
	assert.SolvingSucceeded(&testToTwistedEdwards{}, inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
