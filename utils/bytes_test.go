package utils

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

const (
	prefixLen  = 26
	contentLen = 64
)

type testPrefixedBytesCircuit struct {
	Content  [contentLen]uints.U8
	Prefix   [prefixLen]uints.U8
	Expected [prefixLen + contentLen]uints.U8
}

func (c *testPrefixedBytesCircuit) Define(api frontend.API) error {
	Bytes(append(c.Prefix[:], c.Content[:]...)).AssertIsEqual(api, c.Expected[:])
	return nil
}

func TestPrefixedBytes(t *testing.T) {
	prefix := BytesFromString("\u0019Ethereum Signed Message:\n", prefixLen)
	content := BytesFromString("d03191e177f9ecdd5230e11686b303bfcf770315fd699f2d1e9c12125fdf40f4fc86bb654fbeb6fe243a53768bb29b4ce0d6597e4fe9a85d00d679c64ec6030e7cd8a34e76b00b66e6dcf6003e440fec48daf17015d18f090df614e932f35db092b1ea3d9fbbf56dca5cbf6fbefbe77ae675059dc6c18c349bbddbfcbd45e7bf", contentLen)
	expected := BytesFromString("\u0019Ethereum Signed Message:\nd03191e177f9ecdd5230e11686b303bfcf770315fd699f2d1e9c12125fdf40f4fc86bb654fbeb6fe243a53768bb29b4ce0d6597e4fe9a85d00d679c64ec6030e7cd8a34e76b00b66e6dcf6003e440fec48daf17015d18f090df614e932f35db092b1ea3d9fbbf56dca5cbf6fbefbe77ae675059dc6c18c349bbddbfcbd45e7bf", prefixLen+contentLen)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testPrefixedBytesCircuit{}, &testPrefixedBytesCircuit{
		Prefix:   [prefixLen]uints.U8(prefix),
		Content:  [contentLen]uints.U8(content),
		Expected: [prefixLen + contentLen]uints.U8(expected),
	}, test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(groth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
