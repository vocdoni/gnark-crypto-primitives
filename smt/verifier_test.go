package smt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type testVerifierCircuit struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [160]frontend.Variable
}

func (circuit *testVerifierCircuit) Define(api frontend.API) error {
	return Verifier(api, circuit.Root, circuit.Key, circuit.Value, circuit.Siblings[:])
}

func TestVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit testVerifierCircuit
	noirTestRoot, _ := new(big.Int).SetString("21135506078746510573119705753579567335835726524098367527812922933644667691006", 10)
	noirTestKey, _ := new(big.Int).SetString("500400244448261235194511589700085192056257072811", 10)
	noirTestValue, _ := new(big.Int).SetString("10", 10)
	noirTestSiblings := []string{
		"13175438946403099127785287940793227584022396513432127658229341995655669945927",
		"8906855681626013805208515602420790146700990181185755277830603493975762067087",
		"9457781280074316365191154663065840032069867769247887694941521931147573919101",
		"3886003602968045687040541715852317767887615077999207197223340281752527813105",
		"5615297718669932502221460377065820025799135258753150375139282337562917282190",
		"8028805327216345358010190706209509799652032446863364094962139617192615346584",
		"572541247728029242828004565014369314635015057986897745288271497923406188177",
		"9738042754594087795123752255236264962836518315799343893748681096434196901468",
	}

	encNoirTestSiblings := [160]frontend.Variable{}
	for i := 0; i < 160; i++ {
		if i < len(noirTestSiblings) {
			encNoirTestSiblings[i], _ = new(big.Int).SetString(noirTestSiblings[i], 10)
		} else {
			encNoirTestSiblings[i] = big.NewInt(0)
		}
	}

	inputs := testVerifierCircuit{
		Root:     noirTestRoot,
		Key:      noirTestKey,
		Value:    noirTestValue,
		Siblings: encNoirTestSiblings,
	}
	assert.SolvingSucceeded(&circuit, &inputs, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
